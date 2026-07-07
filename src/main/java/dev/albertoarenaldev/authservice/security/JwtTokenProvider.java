package dev.albertoarenaldev.authservice.security;

import dev.albertoarenaldev.authservice.modelo.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * Genera y valida access tokens (JWT) usando JJWT 0.12.5.
 *
 * <p>Los <b>refresh tokens NO se generan aquí</b>: son tokens opacos
 * hasheados en la DB (entidad {@code RefreshToken}) para permitir
 * revocación inmediata y detección de reuso de tokens robados. Esto
 * también encaja con la arquitectura del proyecto: el access token es
 * stateless (JWT), el refresh token es stateful (DB).
 *
 * <p>Algoritmo: HS256 (HMAC-SHA256). El secret se convierte a bytes
 * UTF-8; debe tener >= 32 bytes (256 bits) o {@link Keys#hmacShaKeyFor}
 * lanza {@code WeakKeyException} al construir este bean.
 */
@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtProperties jwtProperties;
    private final SecretKey signingKey;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signingKey = Keys.hmacShaKeyFor(
                jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Genera un access token firmado para el usuario.
     *
     * <p>Claims:
     * <ul>
     *   <li>{@code sub} — email del usuario (identidad)</li>
     *   <li>{@code iss} — issuer (de {@link JwtProperties#getIssuer()})</li>
     *   <li>{@code iat} — fecha de emisión</li>
     *   <li>{@code exp} — fecha de expiración</li>
     *   <li>{@code roles} — lista de nombres de roles (p. ej. {@code ["ROLE_USER"]})</li>
     * </ul>
     */
    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(jwtProperties.getAccessTokenExpirationMs());

        List<String> roleNames = user.getRoles().stream()
                .map(role -> role.getName())
                .toList();

        return Jwts.builder()
                .subject(user.getEmail())
                .issuer(jwtProperties.getIssuer())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim("roles", roleNames)
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Valida firma + expiración del token y devuelve los claims en un solo
     * parse. Devuelve {@link Optional#empty()} si el token es invalido
     * (firma incorrecta, expirado, malformado).
     *
     * <p>Usar este metodo cuando se necesitan los claims despues de validar
     * (caso tipico: el filtro de autenticacion). Asi se evita parsear el
     * token 2 o 3 veces seguidas.
     */
    public Optional<Claims> validateAndGetClaims(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(claims);
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Valida firma + expiración del token. Devuelve {@code true} si es válido.
     * Convenience method que delega en {@link #validateAndGetClaims(String)}.
     */
    public boolean validateToken(String token) {
        return validateAndGetClaims(token).isPresent();
    }

    /**
     * Extrae el email (subject) del token. Asume que el token ya fue validado.
     */
    public String getEmailFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Extrae los roles del claim {@code roles}. Devuelve lista vacía si el
     * claim no existe o no es una lista (defensa contra tokens malformados).
     */
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Object rolesClaim = parseClaims(token).get("roles");
        if (rolesClaim instanceof List<?> list) {
            return (List<String>) list;
        }
        return List.of();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
