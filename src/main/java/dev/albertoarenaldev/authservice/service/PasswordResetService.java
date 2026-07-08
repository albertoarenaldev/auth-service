package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.config.PasswordResetProperties;
import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.PasswordResetToken;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.PasswordResetTokenRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import dev.albertoarenaldev.authservice.service.email.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Optional;

/**
 * Servicio de password reset: gestiona el ciclo de vida de los tokens de
 * restablecimiento de contraseña (tokens opacos persistidos en BD con su
 * hash SHA-256).
 *
 * <p>Responsabilidades:
 * <ul>
 *   <li>{@link #forgotPassword(String)} — recibe un email, lo normaliza
 *       (trim + lowercase) y busca al usuario. Si existe, genera un
 *       token opaco (32 bytes {@code SecureRandom} → Base64 URL-safe sin
 *       padding) y lo persiste hasheado (SHA-256 hex) con el TTL de
 *       {@code app.jwt.password-reset-token-expiration-ms}. Después
 *       envía el correo con el enlace de reset. Si el email NO existe,
 *       registra un evento de auditoría pero NO envía correo ni
 *       diferencia la respuesta al cliente (mitigación contra
 *       <em>user enumeration</em> según OWASP).</li>
 *   <li>{@link #resetPassword(String, String)} — recibe token raw +
 *       nueva contraseña. Valida el token (existencia, no expirado,
 *       no usado, usuario asociado habilitado), marca el token como
 *       usado, actualiza el {@code passwordHash} del usuario y
 *       <b>revoca todos los refresh tokens activos del usuario</b>,
 *       todo dentro de una sola transacción. La revocation de refresh
 *       tokens es la defensa en profundidad de OWASP contra sesiones
 *       persistentes tras un cambio de contraseña: aunque un atacante
 *       tuviera un refresh token robado, el reset lo invalida. Si
 *       algo falla, todas las operaciones se rollbackean. Devuelve
 *       {@code void}; el controlador responde 204 No Content.</li>
 * </ul>
 *
 * <p><b>Limitación conocida del flujo password-reset:</b> el access
 * token JWT sigue siendo válido hasta su expiración natural (15 min)
 * tras un reset. La {@link TokenService#revokeAllForUser(Long)} sólo
 * invalida refresh tokens — si quisiéramos bloquear el JWT actual
 * sería necesaria una blocklist server-side (Redis), planificada para
 * Fase 7. En la práctica, el atacante con un JWT válido puede seguir
 * usando el access durante <=15 min, pero el refresh falla y debe
 * re-autenticarse.</p>
 *
 * <p><b>Por qué SHA-256 (no BCrypt) para hashear el reset token:</b>
 * mismo argumento que {@link TokenService}. BCrypt es deliberadamente
 * lento (~250ms) para frustrar fuerza bruta sobre contraseñas débiles.
 * El reset token tiene 256 bits de entropía (fuerza bruta imposible),
 * así que la lentitud de BCrypt solo añadiría ~250ms de latencia
 * innecesaria a cada petición de reset. SHA-256 es ~1µs y suficiente.
 *
 * <p><b>Defensa en profundidad (revocación de sesiones):</b>
 * {@link #resetPassword} llama a {@link TokenService#revokeAllForUser(Long)}
 * tras actualizar el {@code passwordHash}. Esto invalida TODOS los
 * refresh tokens persistidos del usuario en {@code refresh_tokens}
 * (filtra por {@code revoked_at IS NULL}). Como ambas operaciones viven
 * dentro del mismo {@code @Transactional} (REQUIRED se une a la TX
 * abierta), la atomicidad se preserva: si la revocation falla, el
 * update de password hace rollback y el estado del usuario permanece
 * intacto (puede reintentar con el mismo token).</p>
 *
 * <p><b>Política de fallo del envío SMTP:</b> {@link SmtpEmailSender} captura
 * internamente {@code MailException} y solo loguea (no propaga), así que un
 * fallo del SMTP en producción NUNCA devuelve excepción al cliente. Si por
 * algún motivo {@link EmailSender} lanza algo inesperado (p.ej. NPE por bug
 * nuestro), {@code GlobalExceptionHandler} lo traducirá a HTTP 500 — el
 * detalle se loguea en {@code ERROR} y el equipo puede alertar vía
 * Sentry/monitoring. La idempotencia es funcional: el usuario puede llamar
 * de nuevo a {@code forgotPassword} y se generará un token nuevo (el viejo
 * expirará a los 15 min y la limpieza programada lo purga).
 *
 * <p><b>Rate limit:</b> no se implementa en Fase 5 por decisión de scope.
 * Planificado para Fase 7 (cuenta de tokens de reset creados por email
 * en una ventana de tiempo). Migrar a {@code @Async} se puede hacer en
 * el mismo hito sin tocar este contrato — el método ya devuelve void.
 *
 * <p><b>PII en logs:</b> nunca se loguea el email en claro ni el token.
 * Para emails se usa un prefijo MD5 de 8 chars (no criptográfico,
 * estrictamente tagging); para tokens se loguea un prefijo de 8 chars
 * del SHA-256 hash.
 */
@Service
public class PasswordResetService {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetService.class);

    // La generación + hashing del token se delega a {@link SecureTokenHasher},
    // clase compartida con {@link TokenService}. DRY: ambos tokens (refresh +
    // reset) usan exactamente la misma estrategia (32 bytes SecureRandom +
    // SHA-256 hex).

    /** Subject del correo (internacionalizado en español para Fase 5). */
    private static final String EMAIL_SUBJECT = "Restablece tu contraseña";

    /**
     * Cuerpo del correo en texto plano. {@code %s} placeholders para
     * {@code appName}, {@code resetUrl}, {@code expirationMinutes}.
     * Mantenido en español; i18n se añade cuando exista i18n real del
     * frontend (Fase 6+).
     */
    private static final String EMAIL_BODY_TEMPLATE = """
            Hola,

            Has solicitado restablecer tu contraseña en %1$s.

            Haz clic en el siguiente enlace (o pégalo en tu navegador):

            %2$s

            Este enlace expira en %3$d minutos. Pasado ese plazo deberás
            solicitar un nuevo enlace.

            Si no has solicitado este cambio, puedes ignorar este mensaje
            de forma segura — tu contraseña actual permanecerá intacta.

            —
            Equipo %1$s
            """;

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final EmailSender emailSender;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final PasswordResetProperties resetProperties;
    private final long tokenExpirationMs;

    public PasswordResetService(UserRepository userRepository,
                                PasswordResetTokenRepository tokenRepository,
                                EmailSender emailSender,
                                PasswordEncoder passwordEncoder,
                                TokenService tokenService,
                                PasswordResetProperties resetProperties,
                                JwtProperties jwtProperties) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.emailSender = emailSender;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.resetProperties = resetProperties;
        this.tokenExpirationMs = jwtProperties.getPasswordResetTokenExpirationMs();
    }

    // ============================================================
    // Public API
    // ============================================================

    /**
     * Inicia el flujo de password reset para un email. NO revela si el
     * email está registrado (mitigación contra user-enumeration). Si el
     * usuario existe: genera token, persiste hash y envía correo. Si no
     * existe: registra un evento de auditoría y sale silenciosamente.
     *
     * <p>El caller (controlador) responde siempre 202 Accepted.
     *
     * @param rawEmail email recibido del request (sin normalizar)
     */
    @Transactional
    public void forgotPassword(String rawEmail) {
        String email = normalizeEmail(rawEmail);
        String emailTag = md5Prefix(email);

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            // Silencio al cliente; trazabilidad interna con prefijo MD5
            // del email para no leakear PII al log.
            log.warn("Password reset requested for non-existent email: {}", emailTag);
            // Anti-enumeracion por tiempo (OWASP). El path "usuario existe"
            // hace DB insert + SHA-256 + envio de correo (~5-15 ms).
            // El path "no existe" sin dummy seria ~2-3 ms (solo DB lookup).
            // Un atacante midiendo latencia HTTP podria distinguir ambos casos.
            // Quemamos ~100-250 ms con un bcrypt encode ficticio para igualar
            // ambos paths. El resultado se descarta.
            passwordEncoder.encode(java.util.UUID.randomUUID().toString());
            return;
        }

        User user = userOpt.get();

        // Invalidar tokens de reset activos previos del usuario. Si el
        // usuario pidio 3 resets en 5 minutos, los 3 correos se envian
        // pero solo el ultimo token es valido. Cierra la ventana de
        // ataque contra tokens viejos interceptados (defense in depth).
        Instant now = Instant.now();
        int invalidated = tokenRepository.invalidateActiveTokensForUser(user.getId(), now);
        if (invalidated > 0) {
            log.info("Invalidated {} previous active reset token(s) for user id={} before issuing new one",
                    invalidated, user.getId());
        }

        String rawToken = SecureTokenHasher.generateRawToken();
        String tokenHash = SecureTokenHasher.hashToken(rawToken);

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUser(user);
        resetToken.setTokenHash(tokenHash);
        resetToken.setExpiresAt(now.plusMillis(tokenExpirationMs));
        tokenRepository.save(resetToken);

        // Construir URL absoluta + cuerpo del correo.
        String resetUrl = resetProperties.getBaseUrl() + "?token=" + rawToken;
        long expirationMinutes = tokenExpirationMs / 60_000;
        String body = String.format(EMAIL_BODY_TEMPLATE,
                resetProperties.getAppName(), resetUrl, expirationMinutes);

        emailSender.send(email, EMAIL_SUBJECT, body);
        log.info("Password reset link sent for user id={} email={}",
                user.getId(), emailTag);
    }

    /**
     * Canjea un token de reset y actualiza la contraseña del usuario.
     * Atómico: marcar el token como usado y actualizar el passwordHash
     * suceden en la misma transacción.
     *
     * @param rawToken     token que el usuario recibió por correo (en claro)
     * @param newPassword  nueva contraseña en claro (se hashea aquí con
     *                     {@link PasswordEncoder})
     * @throws InvalidTokenException si el token no existe, expiró, ya se
     *         usó, o si el usuario asociado está deshabilitado.
     *         Mapeado a HTTP 401 por {@code GlobalExceptionHandler}.
     */
    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        String tokenHash = SecureTokenHasher.hashToken(rawToken);

        PasswordResetToken token = tokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> {
                    log.warn("Password reset failed: token not found (hash={})", shortHash(tokenHash));
                    return new InvalidTokenException("Invalid or expired reset token");
                });

        // Validaciones de estado del token. Cada fallo produce el MISMO mensaje
        // genérico al cliente (mitigación contra oráculo: el atacante no debe
        // poder distinguir "no existe" de "expirado" de "ya usado").
        if (token.getUsedAt() != null) {
            log.warn("Password reset failed: token already used (hash={})", shortHash(tokenHash));
            throw new InvalidTokenException("Invalid or expired reset token");
        }
        if (token.getExpiresAt().isBefore(Instant.now())) {
            log.warn("Password reset failed: token expired (hash={})", shortHash(tokenHash));
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        User user = token.getUser();
        if (user == null || !user.isEnabled()) {
            log.warn("Password reset failed: associated user missing or disabled (userId={})",
                    user != null ? user.getId() : null);
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        // Marcar token como usado + actualizar password — atomicidad garantizada
        // por @Transactional: si passwordEncoder o save() fallan, AMBOS cambios
        // se rollbackean, dejando el estado intacto y permitiendo reintento
        // con el mismo token.
        token.setUsedAt(Instant.now());
        tokenRepository.save(token);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Defensa en profundidad (OWASP ASVS V3.5 / V6): tras un cambio de
        // password, todas las sesiones existentes deben invalidarse. Un
        // atacante con un refresh token robado pero sin el password nuevo
        // queda bloqueado — el refresh que presentará tras el reset vence
        // y la sesion se destruye. Ambas operaciones viven dentro del mismo
        // @Transactional: si la revocacion falla, el update de password
        // hace rollback (el token sigue valido, el usuario puede reintentar).
        int revokedSessions = tokenService.revokeAllForUser(user.getId());
        log.info("Password reset successful for user id={} ({} refresh token(s) revoked)",
                user.getId(), revokedSessions);
    }

    // ============================================================
    // Helpers: SecureTokenHasher (generación + hashing, compartido)
    //          normalizeEmail, md5Prefix, shortHash (locales, específicos del flujo)
    // ============================================================

    /**
     * Email → {@code trim().toLowerCase()}. Necesario porque
     * {@code UserRepository.findByEmail} es case-sensitive (Hibernate
     * deriva la query sin COLLATE). Sin esta normalización, dos emails
     * del mismo usuario con distinto case ({@code Alice@x.com} vs
     * {@code alice@x.com}) se tratarían como usuarios distintos.
     */
    private String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    /**
     * MD5 hex primeros 8 chars — prefijo anónimo para tagging en logs
     * sin leakear el email en claro. NO usar con fines de seguridad
     * (MD5 es débil); uso exclusivo de observabilidad.
     */
    private String md5Prefix(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(8);
            for (int i = 0; i < 4; i++) {
                String h = Integer.toHexString(0xff & hash[i]);
                if (h.length() == 1) hex.append('0');
                hex.append(h);
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            return "anon";
        }
    }

    /**
     * Primeros 8 chars del SHA-256 hash — para logging cuando NO queremos
     * leakear el token entero (que sería equivalente a leakearlo). Es
     * identificar-en-grupo, no un secreto: dos tokens diferentes
     * tienen alta probabilidad de prefijo distinto (efecto avalancha).
     */
    private String shortHash(String full) {
        return full.length() <= 8 ? full : full.substring(0, 8);
    }
}
