package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ChangePasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.UpdateProfileRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.exception.EmailAlreadyExistsException;
import dev.albertoarenaldev.authservice.exception.InvalidCredentialsException;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.service.TokenService.TokenPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

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

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       TokenService tokenService,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
    }

    // ============================================================
    // Registro
    // ============================================================

    /**
     * Registra un nuevo usuario con el rol por defecto (ROLE_USER) y emite
     * el primer par de tokens.
     *
     * <p>Si la BD no tiene el rol (p. ej. primer arranque en un entorno
     * donde el seed de roles no se ha ejecutado), se crea al vuelo de forma
     * idempotente. Asi el endpoint funciona incluso en una BD vacia.
     *
     * @throws EmailAlreadyExistsException si el email ya esta registrado
     */
    @Transactional
    public AuthResponse register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.email())) {
            throw new EmailAlreadyExistsException(req.email());
        }

        // El rol por defecto (ROLE_USER) es creado por DataSeeder al arranque.
        // Si no existe, es un bug de configuracion (DataSeeder no se ejecuto).
        Role defaultRole = roleRepository.findByName(DEFAULT_ROLE_NAME)
                .orElseThrow(() -> new IllegalStateException(
                        "Default role " + DEFAULT_ROLE_NAME + " not found. DataSeeder should have created it on startup."));

        User user = new User();
        user.setEmail(req.email());
        user.setPasswordHash(passwordEncoder.encode(req.password()));
        user.setFirstName(req.firstName());
        user.setLastName(req.lastName());
        user.setEnabled(true);
        user.addRole(defaultRole);

        User saved = userRepository.save(user);
        log.info("Registered new user id={} email={}", saved.getId(), saved.getEmail());

        return buildAuthResponse(saved);
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
            throw new InvalidCredentialsException();
        }

        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        log.info("User id={} logged in successfully", user.getId());

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
}
