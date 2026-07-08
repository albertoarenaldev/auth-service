package dev.albertoarenaldev.authservice.modelo;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;

/**
 * PasswordResetToken entity — token de un solo uso para resetear contraseña.
 * Se genera al hacer {@code POST /password/forgot} y se envía por email al
 * usuario. Se marca como usado al hacer {@code POST /password/reset}.
 *
 * <p>Igual que {@link RefreshToken}, el token se guarda hasheado (SHA-256) y
 * tiene expiración corta (1h por defecto). Un solo uso: una vez consumido,
 * el hash deja de ser válido aunque no haya expirado.
 */
@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {

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

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    /**
     * Version para optimistic locking de Hibernate (auditoria finding #4).
     * Protege contra una race condition teorica: dos requests concurrentes
     * con el mismo token ambos pasaban la validacion (usedAt=null) y ambos
     * intentaban marcar el token como usado. Sin @Version, ambas escrituras
     * tenian exito (last write wins); con @Version, la segunda escritura
     * falla con {@code ObjectOptimisticLockingFailureException}, que el
     * servicio traduce a {@code InvalidTokenException} (HTTP 401 generico,
     * mismo mensaje que "token ya usado" — el cliente no distingue ambos
     * casos, evitando un canal lateral de informacion).
     *
     * <p><b>Por que solo 1 de N debe tener exito (OWASP):</b> la regla
     * "un solo uso" del reset token es una invariante de seguridad. Si
     * dos requests pasan la validacion simultaneamente y ambos marcan
     * el token como usado, el segundo request tambien actualizaria el
     * password del usuario (al mismo valor o a uno distinto) y revocaria
     * los refresh tokens. El impacto funcional es minimo (mismo password
     * o diferente, en cualquier caso el resultado es seguro), pero la
     * condicion de carrera es un bug logico que rompe la invariante
     * "una operacion de reset por token".
     */
    @Version
    @Column(name = "version")
    private Long version;

    public PasswordResetToken() {
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
    }

    // ----- Helpers -----

    public boolean isUsed() {
        return usedAt != null;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isValid() {
        return !isUsed() && !isExpired();
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

    public Instant getUsedAt() {
        return usedAt;
    }

    public void setUsedAt(Instant usedAt) {
        this.usedAt = usedAt;
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
