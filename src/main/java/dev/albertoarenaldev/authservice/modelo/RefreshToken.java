package dev.albertoarenaldev.authservice.modelo;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;

/**
 * RefreshToken entity — token opaco (UUID) hasheado en BD (SHA-256).
 * Permite revocación centralizada inmediata y rotación por reuso.
 *
 * <p>El token NUNCA se guarda en plano. Solo su hash SHA-256. Si roban la BD,
 * los tokens no se pueden usar (no se puede invertir el hash sin fuerza bruta).
 *
 * <p>Rotación: cada vez que el cliente hace {@code /auth/refresh}, el token
 * viejo se marca con {@code revokedAt} y se emite uno nuevo. Si el viejo se
 * vuelve a usar (reuso de token robado), se detecta y se revoca toda la familia.
 */
@Entity
@Table(
        name = "refresh_tokens",
        indexes = {
                // Hash único (columna ya tiene unique=true, índice creado automático)
                @Index(name = "idx_refresh_expires_at", columnList = "expires_at")
        }
)
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "token_hash", nullable = false, unique = true, length = 255)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "replaced_by_token_id")
    private Long replacedByTokenId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Version para optimistic locking de Hibernate (auditoria finding #4,
     * aplicado por consistencia con {@link PasswordResetToken}).
     *
     * <p>Protege contra dos races teoricas en el ciclo de vida del
     * refresh token:
     * <ul>
     *   <li><b>Rotacion concurrente:</b> dos requests simultaneos con
     *       el mismo refresh token (caso tipico de doble-click del
     *       cliente). Sin @Version, ambos podrian leer el token viejo
     *       y emitir uno nuevo, generando dos cadenas de rotacion
     *       paralelas. Con @Version, el segundo UPDATE falla con
     *       {@code ObjectOptimisticLockingFailureException}, que
     *       {@link TokenService} traduce a {@code InvalidTokenException}
     *       (HTTP 401).</li>
     *   <li><b>Revocacion concurrente:</b> si dos procesos intentan
     *       revocar el mismo token simultaneamente (e.g. logout
     *       concurrente con deteccion de reuso), solo uno tendra exito.</li>
     * </ul>
     *
     * <p>El impact funcional sin @Version era minimo (mismo hash, mismo
     * usuario), pero la condicion de carrera rompia la invariante "una
     * sola rotacion activa por token".
     */
    @Version
    @Column(name = "version")
    private Long version;

    public RefreshToken() {
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
    }

    // ----- Helpers -----

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !isRevoked() && !isExpired();
    }

    // ----- Getters / setters -----

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public Long getReplacedByTokenId() {
        return replacedByTokenId;
    }

    public void setReplacedByTokenId(Long replacedByTokenId) {
        this.replacedByTokenId = replacedByTokenId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }
}
