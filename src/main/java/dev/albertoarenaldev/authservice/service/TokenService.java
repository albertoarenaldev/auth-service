package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import io.micrometer.core.instrument.Counter;
import dev.albertoarenaldev.authservice.modelo.AuditEventType;
import dev.albertoarenaldev.authservice.modelo.RefreshToken;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.RefreshTokenRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import dev.albertoarenaldev.authservice.security.JwtTokenProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Servicio de tokens: gestiona el ciclo de vida de los refresh tokens
 * (tokens opacos persistidos en BD con su hash SHA-256).
 *
 * <p>Responsabilidades:
 * <ul>
 *   <li>Generar refresh tokens: 32 bytes de {@link SecureRandom} codificados
 *       en Base64 URL-safe sin padding (~43 chars, 256 bits de entropia).</li>
 *   <li>Hashear el token antes de persistirlo (SHA-256 hex). La BD NUNCA
 *       ve el token en claro. Si roban la BD, los tokens no se pueden
 *       usar (no se puede invertir SHA-256 sin fuerza bruta).</li>
 *   <li>Rotar tokens: marcar el viejo como {@code revokedAt} +
 *       {@code replacedByTokenId} y emitir uno nuevo. Esto da trazabilidad
 *       de la cadena y permite deteccion de reuso.</li>
 *   <li>Detectar reuso: si se presenta un refresh token que ya estaba
 *       revocado Y habia sido reemplazado (no expiracion natural), se
 *       asume que un atacante lo robo y se revocan TODOS los tokens
 *       activos del usuario (mitigacion contra token theft).</li>
 *   <li>Revocar tokens concretos (logout de un dispositivo) o todos los
 *       tokens de un usuario (logout global, cambio de password).</li>
 * </ul>
 *
 * <p><b>Por que SHA-256 y no BCrypt para hashear refresh tokens:</b>
 * BCrypt es deliberadamente lento (~250ms) para frustrar fuerza bruta
 * sobre contraseñas débiles. Los refresh tokens tienen 256 bits de entropía
 * (fuerza bruta imposible), asi que la lentitud de BCrypt solo aniadiria
 * latencia innecesaria a cada peticion de refresh. SHA-256 es ~1us y
 * suficiente.
 *
 * <p>El access token JWT NO se genera aqui directamente: se delega en
 * {@link JwtTokenProvider}. Este servicio solo orquesta el lado stateful
 * (refresh tokens persistidos).
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    // La generación + hashing del token se delega a {@link SecureTokenHasher},
    // clase compartida con {@link PasswordResetService}. DRY: ambos tokens
    // (refresh + reset) usan exactamente la misma estrategia (32 bytes
    // SecureRandom + SHA-256 hex).

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final long refreshTtlMs;
    private final AuditService auditService;
    private final Counter tokenRefreshCounter;
    private final Counter tokenReuseCounter;

    public TokenService(RefreshTokenRepository refreshTokenRepository,
                        JwtTokenProvider jwtTokenProvider,
                        JwtProperties jwtProperties,
                        AuditService auditService,
                        Counter tokenRefreshCounter,
                        Counter tokenReuseCounter) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTtlMs = jwtProperties.getRefreshTokenExpirationMs();
        this.auditService = auditService;
        this.tokenRefreshCounter = tokenRefreshCounter;
        this.tokenReuseCounter = tokenReuseCounter;
    }

    // ============================================================
    // Access token (delegacion)
    // ============================================================

    /**
     * Genera un access token JWT firmado para el usuario.
     * <p>Delegacion directa a {@link JwtTokenProvider} para centralizar
     * la creacion de tokens en un unico punto.
     */
    public String generateAccessToken(User user) {
        return jwtTokenProvider.generateAccessToken(user);
    }

    // ============================================================
    // Refresh tokens
    // ============================================================

    /**
     * Emite un nuevo refresh token para el usuario y lo persiste (hasheado).
     *
     * @return el token raw (en claro). Es el UNICO momento en que el cliente
     *         lo vera; la BD solo guarda el hash.
     */
    @Transactional
    public String generateRefreshToken(User user) {
        String rawToken = SecureTokenHasher.generateRawToken();
        String hash = SecureTokenHasher.hashToken(rawToken);
        Instant now = Instant.now();

        RefreshToken entity = new RefreshToken();
        entity.setUser(user);
        entity.setTokenHash(hash);
        entity.setExpiresAt(now.plusMillis(refreshTtlMs));
        refreshTokenRepository.save(entity);

        log.debug("Issued refresh token for user id={}", user.getId());
        return rawToken;
    }

    /**
     * Rota un refresh token: valida el presentado, marca el viejo como
     * usado ({@code revokedAt} + {@code replacedByTokenId}) y emite uno
     * nuevo.
     *
     * <p><b>Deteccion de reuso:</b> si el token presentado ya estaba
     * revocado Y fue reemplazado por otro (campo {@code replacedByTokenId}
     * no nulo), interpretamos que un atacante esta reusando un token
     * robado. En ese caso revocamos TODOS los tokens activos del usuario
     * y lanzamos excepcion. Esto mitiga el robo: si te roban el refresh
     * token pero el legitimo usuario ya lo roto, el atacante no puede
     * ni siquiera canjearlo sin delatar el compromiso.
     *
     * @param rawOldToken el refresh token actual del cliente (en claro)
     * @return TokenPair con el nuevo access + refresh
     * @throws InvalidTokenException si el token no existe, expiro, o se
     *         detecta reuso (familia comprometida)
     */
    @Transactional
    public TokenPair rotateRefreshToken(String rawOldToken) {
        String oldHash = SecureTokenHasher.hashToken(rawOldToken);
        RefreshToken old = refreshTokenRepository.findByTokenHash(oldHash)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        // --- Validacion de estado ---
        if (old.isRevoked()) {
            if (old.getReplacedByTokenId() != null) {
                // Reuso: el token ya fue rotado por una peticion de refresh
                // anterior. Un reuso aqui indica que el legitimo usuario YA
                // uso este token (o que un atacante lo uso primero y el
                // legitimo lo intento despues). En cualquier caso, la familia
                // esta comprometida: revocamos TODOS los tokens del usuario.
                log.warn("Refresh token reuse detected for user id={} - revoking entire family",
                        old.getUser().getId());
                auditService.record(AuditEventType.TOKEN_REUSE_DETECTED, old.getUser(),
                        "token_id=" + old.getId());
                tokenReuseCounter.increment();
                this.revokeAllForUser(old.getUser().getId());
                // Mensaje generico para no leakear al cliente la razon del fallo.
                // El log.warn de arriba mantiene la distincion server-side.
                throw new InvalidTokenException("Invalid refresh token");
            }
            // Token revocado manualmente (logout, logout global, etc.) pero
            // NO rotado. El cliente intento reusar un refresh token que ya
            // cerro sesion: debe fallar.
            throw new InvalidTokenException("Invalid refresh token");
        }

        // --- Expiration check ---
        if (old.isExpired()) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        // --- Emit new refresh token ---
        String newRaw = SecureTokenHasher.generateRawToken();
        String newHash = SecureTokenHasher.hashToken(newRaw);
        Instant now = Instant.now();

        RefreshToken newEntity = new RefreshToken();
        newEntity.setUser(old.getUser());
        newEntity.setTokenHash(newHash);
        newEntity.setExpiresAt(now.plusMillis(refreshTtlMs));
        newEntity = refreshTokenRepository.save(newEntity);

        // --- Mark old as rotated (link to new) ---
        old.setRevokedAt(now);
        old.setReplacedByTokenId(newEntity.getId());
        refreshTokenRepository.save(old);

        // --- Issue new access token ---
        String newAccess = jwtTokenProvider.generateAccessToken(old.getUser());

        log.debug("Rotated refresh token for user id={}", old.getUser().getId());
        auditService.record(AuditEventType.TOKEN_REFRESHED, old.getUser(),
                "old_token_id=" + old.getId() + " new_token_id=" + newEntity.getId());
        tokenRefreshCounter.increment();
        return new TokenPair(newAccess, newRaw, old.getUser());
    }

    /**
     * Revoca un refresh token concreto (logout de un solo dispositivo).
     * No falla si el token no existe (idempotente).
     */
    @Transactional
    public void revokeRefreshToken(String rawToken) {
        String hash = SecureTokenHasher.hashToken(rawToken);
        refreshTokenRepository.findByTokenHash(hash).ifPresent(token -> {
            if (!token.isRevoked()) {
                token.setRevokedAt(Instant.now());
                refreshTokenRepository.save(token);
                log.debug("Revoked refresh token id={}", token.getId());
            }
        });
    }

    /**
     * Revoca todos los refresh tokens activos de un usuario. Usado en:
     * <ul>
     *   <li>Logout global (el usuario cierra sesion en todos los dispositivos)</li>
     *   <li>Cambio de password (las sesiones existentes dejan de ser validas)</li>
     *   <li>Deteccion de reuso (mitigacion contra token theft)</li>
     * </ul>
     *
     * @return numero de tokens revocados
     */
    @Transactional
    public int revokeAllForUser(Long userId) {
        int revoked = refreshTokenRepository.revokeAllByUserId(userId, Instant.now());
        log.debug("Revoked {} refresh tokens for user id={}", revoked, userId);
        if (revoked > 0) {
            auditService.record(AuditEventType.TOKENS_REVOKED,
                    "user_id=" + userId + " count=" + revoked);
        }
        return revoked;
    }

    // ============================================================
    // Helpers: ver SecureTokenHasher (extraído para reutilización).
    // ============================================================

    /**
     * Par (access token, refresh token, User) emitido tras un login o un
     * refresh exitoso. Record inmutable.
     *
     * <p>Se incluye el {@link User} para que el caller (tipicamente
     * {@code AuthService}) pueda construir el {@code UserResponse} del
     * {@code AuthResponse} sin tener que hacer un lookup extra en la DB:
     * el User ya se cargo al validar el refresh token viejo.</p>
     */
    public record TokenPair(String accessToken, String refreshToken, User user) {}
}
