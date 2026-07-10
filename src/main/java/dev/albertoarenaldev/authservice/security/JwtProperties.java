package dev.albertoarenaldev.authservice.security;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * JWT config — bindea el prefijo {@code app.jwt.*} desde application.properties.
 *
 * <p>Las expiraciones se expresan en milisegundos. El {@code secret} debe
 * tener >= 32 bytes (256 bits) para HS256 — si es más corto, JJWT lanza
 * {@code WeakKeyException} al construir la {@link io.jsonwebtoken.security.SecretKey}.
 *
 * <p>Se valida con {@link Validated} al construir el bean: si falta una
 * propiedad, la app falla al arrancar con un mensaje claro (no en runtime
 * con un NullPointerException en mitad de un request).
 */
@ConfigurationProperties(prefix = "app.jwt")
@Validated
public class JwtProperties {

    @NotBlank
    private String secret;

    @NotBlank
    private String issuer;

    @NotNull
    @Positive
    private Long accessTokenExpirationMs;

    @NotNull
    @Positive
    private Long refreshTokenExpirationMs;

    @NotNull
    @Positive
    private Long passwordResetTokenExpirationMs;

    @NotNull
    @Positive
    private Long emailVerificationTokenExpirationMs;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public Long getAccessTokenExpirationMs() {
        return accessTokenExpirationMs;
    }

    public void setAccessTokenExpirationMs(Long accessTokenExpirationMs) {
        this.accessTokenExpirationMs = accessTokenExpirationMs;
    }

    public Long getRefreshTokenExpirationMs() {
        return refreshTokenExpirationMs;
    }

    public void setRefreshTokenExpirationMs(Long refreshTokenExpirationMs) {
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    public Long getPasswordResetTokenExpirationMs() {
        return passwordResetTokenExpirationMs;
    }

    public void setPasswordResetTokenExpirationMs(Long passwordResetTokenExpirationMs) {
        this.passwordResetTokenExpirationMs = passwordResetTokenExpirationMs;
    }

    public Long getEmailVerificationTokenExpirationMs() {
        return emailVerificationTokenExpirationMs;
    }

    public void setEmailVerificationTokenExpirationMs(Long emailVerificationTokenExpirationMs) {
        this.emailVerificationTokenExpirationMs = emailVerificationTokenExpirationMs;
    }
}
