package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.config.PasswordResetProperties;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ChangePasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.UpdateProfileRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.exception.EmailAlreadyExistsException;
import dev.albertoarenaldev.authservice.exception.InvalidCredentialsException;
import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.AuditEventType;
import dev.albertoarenaldev.authservice.modelo.EmailVerificationToken;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.EmailVerificationTokenRepository;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import dev.albertoarenaldev.authservice.service.TokenService.TokenPair;
import io.micrometer.core.instrument.Counter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Servicio de autenticacion: orquesta los flujos de registro, login,
 * refresh de tokens y logout.
 *
 * <p>Es el punto de entrada unico para el {@code AuthController}: no se
 * inyecta ningun repository directamente en el controller, todo pasa por
 * aqui. Esto centraliza:
 * <ul>
 *   <li>Las validaciones de negocio (email duplicado, cuenta deshabilitada).</li>
 *   <li>El hasheo y verificacion de passwords con BCrypt.</li>
 *   <li>La gestion de la transaccion (cada operacion es atomica).</li>
 *   <li>La generacion del par access+refresh via {@link TokenService}.</li>
 * </ul>
 *
 * <p>Convenciones de errores:
 * <ul>
 *   <li>{@link EmailAlreadyExistsException} (409) - email ya registrado.</li>
 *   <li>{@link InvalidCredentialsException} (401) - login fallido. El mensaje
 *       es generico a proposito para no revelar si el email existe o si la
 *       cuenta esta deshabilitada (prevencion de user enumeration).</li>
 * </ul>
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    /** Nombre del rol por defecto asignado a todo usuario nuevo. */
    private static final String DEFAULT_ROLE_NAME = "ROLE_USER";

    /** Subject del correo de verificacion. */
    private static final String VERIFY_EMAIL_SUBJECT = "Verifica tu cuenta";

    /**
     * Cuerpo del correo de verificacion en texto plano.
     * %1$s = appName, %2$s = verifyUrl, %3$d = expirationHours.
     */
    private static final String VERIFY_EMAIL_BODY = """
            Hola,

            Gracias por registrarte en %1$s.

            Para activar tu cuenta, haz clic en el siguiente enlace:

            %2$s

            Este enlace expira en %3$d horas.

            Si no has creado esta cuenta, puedes ignorar este mensaje.

            —
            Equipo %1$s
            """;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationTokenRepository verificationTokenRepository;
    private final PasswordResetProperties resetProperties;
    private final long verificationTokenExpirationMs;
    private final ApplicationEventPublisher eventPublisher;
    private final AuditService auditService;
    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter registerCounter;
    private final Counter emailVerifiedCounter;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       TokenService tokenService,
                       PasswordEncoder passwordEncoder,
                       EmailVerificationTokenRepository verificationTokenRepository,
                       PasswordResetProperties resetProperties,
                       JwtProperties jwtProperties,
                       ApplicationEventPublisher eventPublisher,
                       AuditService auditService,
                       Counter loginSuccessCounter,
                       Counter loginFailureCounter,
                       Counter registerCounter,
                       Counter emailVerifiedCounter) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.verificationTokenRepository = verificationTokenRepository;
        this.resetProperties = resetProperties;
        this.verificationTokenExpirationMs = jwtProperties.getEmailVerificationTokenExpirationMs();
        this.eventPublisher = eventPublisher;
        this.auditService = auditService;
        this.loginSuccessCounter = loginSuccessCounter;
        this.loginFailureCounter = loginFailureCounter;
        this.registerCounter = registerCounter;
        this.emailVerifiedCounter = emailVerifiedCounter;
    }

    // ============================================================
    // Registro
    // ============================================================

    /**
     * Registra un nuevo usuario con el rol por defecto (ROLE_USER).
     *
     * <p>La cuenta se crea con {@code enabled = false}: el usuario debe
     * verificar su email antes de poder autenticarse. Se genera un token
     * opaco (32 bytes SecureRandom → SHA-256), se persiste en
     * {@code email_verification_tokens} y se envia por correo de forma
     * asincrona tras el commit de la transaccion.
     *
     * <p>No se emiten tokens JWT ni refresh en este punto: el usuario
     * los recibe al verificar su email via {@link #verifyEmail(String)}.
     *
     * @return representacion publica del usuario creado (sin tokens)
     * @throws EmailAlreadyExistsException si el email ya esta registrado
     */
    @Transactional
    public UserResponse register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new EmailAlreadyExistsException(req.email());
        }

        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE_NAME)
                .orElseThrow(() -> new IllegalStateException(
                        "Default role " + DEFAULT_ROLE_NAME + " not found. DataSeeder should have created it on startup."));

        User user = new User();
        user.setEmail(req.email());
        user.setPasswordHash(passwordEncoder.encode(req.password()));
        user.setFirstName(req.firstName());
        user.setLastName(req.lastName());
        // enabled = false por defecto (ver User.java). El usuario debe
        // verificar su email antes de poder hacer login.
        user.addRole(defaultRole);

        User saved = userRepository.save(user);
        log.info("Registered new user id={} email={} (pending email verification)", saved.getId(), saved.getEmail());
        auditService.record(AuditEventType.REGISTER, saved, "email=" + saved.getEmail());
        registerCounter.increment();

        // Generar token de verificacion y publicar evento para envio de email.
        // El listener lo consume en el pool emailExecutor tras el commit.
        generateAndSendVerificationEmail(saved);

        return UserResponse.from(saved);
    }

    /**
     * Verifica el email del usuario canjeando el token recibido por correo.
     *
     * <p>Flujo:
     * <ol>
     *   <li>Hashea el token raw y lo busca en BD.</li>
     *   <li>Valida que no este expirado ni usado y que el usuario asociado
     *       exista.</li>
     *   <li>Marca el token como usado.</li>
     *   <li>Habilita la cuenta del usuario ({@code enabled = true}).</li>
     *   <li>Emite el primer par de tokens (access + refresh).</li>
     * </ol>
     *
     * <p>Mensajes de error genericos para evitar ataques de tipo oracle
     * (el atacante no puede distinguir "token no existe" de "token expirado"
     * de "token ya usado").
     *
     * @param rawToken token en claro del enlace del correo
     * @return AuthResponse con access + refresh + datos del usuario
     * @throws InvalidTokenException si el token no existe, expiro o ya se uso
     */
    @Transactional
    public AuthResponse verifyEmail(String rawToken) {
        String tokenHash = SecureTokenHasher.hashToken(rawToken);

        EmailVerificationToken token = verificationTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Email verification failed: token not found (hash prefix={})",
                            tokenHash.substring(0, 8));
                    return new InvalidTokenException("Invalid or expired verification token");
                });

        if (token.getUsedAt() != null) {
            log.warn("Email verification failed: token already used (id={})", token.getId());
            throw new InvalidTokenException("Invalid or expired verification token");
        }
        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Email verification failed: token expired (id={})", token.getId());
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        User user = token.getUser();
        if (user == null) {
            log.warn("Email verification failed: token id={} has no associated user", token.getId());
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        token.setUsedAt(Instant.now());
        verificationTokenRepository.save(token);

        user.setEnabled(true);
        userRepository.save(user);
        log.info("Email verified for user id={} email={}", user.getId(), user.getEmail());
        auditService.record(AuditEventType.EMAIL_VERIFIED, user, "email=" + user.getEmail());
        emailVerifiedCounter.increment();

        return buildAuthResponse(user);
    }

    // ============================================================
    // Login
    // ============================================================

    /**
     * Autentica a un usuario por email+password y emite un nuevo par de
     * tokens.
     *
     * <p>Si el email no existe, la cuenta esta deshabilitada, o el password
     * no coincide, lanza {@link InvalidCredentialsException} con el mismo
     * mensaje generico para no permitir user enumeration.
     *
     * <p>El orden de las comprobaciones es deliberado: password SIEMPRE se
     * valida, incluso si la cuenta esta deshabilitada, para que el tiempo
     * de respuesta sea uniforme (~250ms por el BCrypt) y un atacante no
     * pueda inferir la existencia de la cuenta por timing.
     *
     * <p>Actualiza {@code lastLoginAt} como efecto colateral.
     */
    @Transactional
    public AuthResponse login(LoginRequest req) {
        User user = userRepository.findByEmail(req.email())
                .orElseThrow(() -> new InvalidCredentialsException());

        boolean passwordOk = passwordEncoder.matches(req.password(), user.getPasswordHash());
        if (!passwordOk || !user.isEnabled()) {
            log.warn("Failed login attempt for email={}", req.email());
            auditService.record(AuditEventType.LOGIN_FAILURE, AuditService.getClientIp(), "email=" + req.email());
            loginFailureCounter.increment();
            throw new InvalidCredentialsException();
        }

        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        log.info("User id={} logged in successfully", user.getId());
        auditService.record(AuditEventType.LOGIN_SUCCESS, user, "email=" + user.getEmail());
        loginSuccessCounter.increment();

        return buildAuthResponse(user);
    }

    // ============================================================
    // Refresh
    // ============================================================

    /**
     * Emite un nuevo par de tokens rotando el refresh token presentado.
     * La deteccion de reuso y la revocacion de familia se delegan en
     * {@link TokenService#rotateRefreshToken(String)}.
     *
     * @throws InvalidTokenException si el token no existe, expiro, o se
     *         detecta reuso
     */
    @Transactional
    public AuthResponse refresh(RefreshRequest req) {
        TokenPair pair = tokenService.rotateRefreshToken(req.refreshToken());
        return new AuthResponse(
                pair.accessToken(),
                pair.refreshToken(),
                UserResponse.from(pair.user())
        );
    }

    // ============================================================
    // Logout
    // ============================================================

    /**
     * Cierra una sesion concreta revocando el refresh token presentado.
     * Es idempotente: si el token no existe o ya estaba revocado, no
     * lanza excepcion.
     */
    @Transactional
    public void logout(String refreshToken) {
        tokenService.revokeRefreshToken(refreshToken);
    }

    /**
     * Cierra todas las sesiones activas de un usuario (logout global,
     * cambio de password, deteccion de compromiso).
     *
     * @return numero de sesiones revocadas
     */
    @Transactional
    public int logoutAll(Long userId) {
        return tokenService.revokeAllForUser(userId);
    }

    // ============================================================
    // Perfil del usuario autenticado (Fase 6)
    // ============================================================

    /**
     * Obtiene el perfil del usuario autenticado a partir de su email
     * (extraido del JWT por {@code JwtAuthenticationFilter}).
     *
     * <p>Si el usuario no existe en BD (p. ej. fue eliminado tras
     * emitirse el JWT), lanza {@link InvalidCredentialsException}
     * mapeada a 401 por {@code GlobalExceptionHandler}.
     *
     * @param email email del usuario autenticado (principal del
     *              SecurityContext)
     * @return representacion publica del usuario (sin password hash)
     */
    public UserResponse getCurrentUser(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException());
        return UserResponse.from(user);
    }

    /**
     * Actualiza nombre y apellido del usuario autenticado.
     *
     * <p>No actualiza el email (requiere flujo de verificacion
     * separado). Los campos llegan validados por Bean Validation
     * desde el controller.
     *
     * @param email email del usuario autenticado
     * @param req   payload con firstName y lastName
     * @return perfil actualizado
     */
    @Transactional
    public UserResponse updateProfile(String email, UpdateProfileRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException());
        user.setFirstName(req.firstName());
        user.setLastName(req.lastName());
        User saved = userRepository.save(user);
        log.info("User id={} updated profile", saved.getId());
        return UserResponse.from(saved);
    }

    /**
     * Cambia la contraseña del usuario autenticado.
     *
     * <p>Flujo:
     * <ol>
     *   <li>Verifica que {@code currentPassword} coincida con el hash
     *       almacenado. Si no, lanza {@link InvalidCredentialsException}
     *       (mismo mensaje generico que login fallido para no filtrar
     *       informacion).</li>
     *   <li>Hashea la nueva contraseña con BCrypt y la persiste.</li>
     *   <li>Revoca todos los refresh tokens activos del usuario
     *       (OWASP ASVS V3.5 / V6.5.1: invalidar sesiones tras cambio
     *       de credenciales).</li>
     * </ol>
     *
     * <p>Las tres operaciones viven dentro del mismo
     * {@code @Transactional}: si la revocacion falla, el cambio de
     * password hace rollback y el estado previo se preserva.
     *
     * <p><b>Limitacion conocida:</b> el access token JWT actual sigue
     * siendo valido hasta su expiracion natural (15 min). El refresh
     * invalida las sesiones a largo plazo; el cierre completo del
     * access requiere JWT blocklist (Fase 7).
     *
     * @param email email del usuario autenticado
     * @param req   payload con currentPassword y newPassword
     */
    @Transactional
    public void changePassword(String email, ChangePasswordRequest req) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException());

        boolean passwordOk = passwordEncoder.matches(req.currentPassword(), user.getPasswordHash());
        if (!passwordOk) {
            log.warn("Change password failed for user id={}: current password mismatch", user.getId());
            throw new InvalidCredentialsException();
        }

        user.setPasswordHash(passwordEncoder.encode(req.newPassword()));
        userRepository.save(user);

        int revokedSessions = tokenService.revokeAllForUser(user.getId());
        log.info("Password changed for user id={} ({} refresh token(s) revoked)",
                user.getId(), revokedSessions);
        auditService.record(AuditEventType.PASSWORD_CHANGED, user, "sessions_revoked=" + revokedSessions);
    }

    // ============================================================
    // OAuth2 / OIDC (Fase 9)
    // ============================================================

    /**
     * Busca o crea un usuario a partir de un login OAuth2 exitoso.
     *
     * <p>Si el email ya existe en BD, devuelve tokens para ese usuario
     * (independientemente de si se registro con password o con OAuth2).
     * Si no existe, crea un usuario nuevo con {@code enabled = true}
     * (el email ya fue verificado por el provider OAuth2).
     *
     * <p>El usuario OAuth2 no tiene password local: se genera un hash
     * aleatorio que nunca se usara (el login siempre es via OAuth2).
     *
     * @param email     email verificado por el provider OAuth2
     * @param fullName  nombre completo del perfil OAuth2 (o el email si no hay)
     * @return AuthResponse con access + refresh + datos del usuario
     */
    @Transactional
    public AuthResponse findOrCreateOAuth2User(String email, String fullName) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user != null) {
            log.info("OAuth2 login for existing user id={} email={}", user.getId(), email);
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
            auditService.record(AuditEventType.LOGIN_SUCCESS, user, "method=oauth2");
            loginSuccessCounter.increment();
            return buildAuthResponse(user);
        }

        // Crear usuario nuevo: email ya verificado por el provider
        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE_NAME)
                .orElseThrow(() -> new IllegalStateException(
                        "Default role " + DEFAULT_ROLE_NAME + " not found."));

        String[] nameParts = fullName.split(" ", 2);
        String firstName = nameParts[0];
        String lastName = nameParts.length > 1 ? nameParts[1] : "";

        User newUser = new User();
        newUser.setEmail(email);
        newUser.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString()));
        newUser.setFirstName(firstName);
        newUser.setLastName(lastName);
        newUser.setEnabled(true); // Email verificado por el provider
        newUser.addRole(defaultRole);

        User saved = userRepository.save(newUser);
        log.info("Created new user via OAuth2: id={} email={}", saved.getId(), email);            auditService.record(AuditEventType.REGISTER, saved, "email=" + saved.getEmail() + " method=oauth2");
            loginSuccessCounter.increment();

        return buildAuthResponse(saved);
    }

    // ============================================================
    // Reenvio de verificacion de email
    // ============================================================

    /**
     * Reenvia el email de verificacion para un usuario no verificado.
     *
     * <p>Sigue el mismo patron anti-enumeration que
     * {@link PasswordResetService#forgotPassword}: si el email no existe
     * o ya esta verificado, responde silenciosamente (202) sin enviar
     * correo. Si el usuario existe y NO esta verificado, invalida los
     * tokens previos, genera uno nuevo y lo envia de forma asincrona.
     *
     * <p>Incluye dummy {@code passwordEncoder.encode()} en el path
     * "usuario ya verificado" para igualar la latencia y evitar que
     * un atacante distinga por timing.
     *
     * @param rawEmail email recibido del request (sin normalizar)
     */
    @Transactional
    public void resendVerification(String rawEmail) {
        String email = rawEmail == null ? "" : rawEmail.trim().toLowerCase();

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.warn("Resend verification requested for non-existent email");
            passwordEncoder.encode(UUID.randomUUID().toString());
            return;
        }

        if (user.isEnabled()) {
            log.info("Resend verification requested for already-verified user id={}", user.getId());
            passwordEncoder.encode(UUID.randomUUID().toString());
            return;
        }

        // Invalidar tokens previos (defensa en profundidad: solo el ultimo es valido)
        Instant now = Instant.now();
        int invalidated = verificationTokenRepository.invalidateActiveTokensForUser(user.getId(), now);
        if (invalidated > 0) {
            log.info("Invalidated {} previous verification token(s) for user id={}", invalidated, user.getId());
        }

        generateAndSendVerificationEmail(user);
        log.info("Verification email resent for user id={}", user.getId());
        auditService.record(AuditEventType.VERIFICATION_RESENT, user, "email=" + user.getEmail());
    }

    // ============================================================
    // Helpers
    // ============================================================

    /**
     * Construye un {@link AuthResponse} con un nuevo par de tokens para
     * el usuario dado. Punto unico de emision de tokens post-autenticacion.
     */
    private AuthResponse buildAuthResponse(User user) {
        String accessToken = tokenService.generateAccessToken(user);
        String refreshToken = tokenService.generateRefreshToken(user);
        return new AuthResponse(accessToken, refreshToken, UserResponse.from(user));
    }

    /**
     * Genera un token de verificacion de email, lo persiste y publica un
     * evento para el envio asincrono del correo.
     *
     * <p>El correo se envia tras el commit de la transaccion (mismo patron
     * que {@link PasswordResetService#forgotPassword}).
     */
    private void generateAndSendVerificationEmail(User user) {
        String rawToken = SecureTokenHasher.generateRawToken();
        String tokenHash = SecureTokenHasher.hashToken(rawToken);

        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setTokenHash(tokenHash);
        token.setExpiresAt(Instant.now().plusMillis(verificationTokenExpirationMs));
        verificationTokenRepository.save(token);

        String verifyUrl = resetProperties.getVerificationBaseUrl() + "?token=" + rawToken;
        long expirationHours = verificationTokenExpirationMs / 3_600_000;
        String body = String.format(VERIFY_EMAIL_BODY,
                resetProperties.getAppName(), verifyUrl, expirationHours);

        eventPublisher.publishEvent(new EmailVerificationRequestedEvent(
                user.getEmail(), VERIFY_EMAIL_SUBJECT, body));
        log.info("Verification email queued for user id={}", user.getId());
    }
}
