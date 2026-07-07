package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.RefreshToken;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests del query crítico de seguridad: {@code findValidByTokenHash}.
 *
 * <p>Esta query decide si un refresh token presentado por el cliente es
 * válido o no. Si falla (devuelve un token inválido o rechaza uno válido),
 * el sistema entero de refresh tokens queda comprometido.
 *
 * <p>Cubre los 4 casos:
 * <ul>
 *   <li>Token válido (existe, no revocado, no expirado) → {@code isPresent}</li>
 *   <li>Token expirado → {@code isEmpty}</li>
 *   <li>Token revocado → {@code isEmpty}</li>
 *   <li>Token inexistente → {@code isEmpty}</li>
 * </ul>
 */
@DataJpaTest
@ActiveProfiles("test")
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private TestEntityManager entityManager;

    private User testUser;

    @BeforeEach
    void setUp() {
        // Rol seed (no usamos ROLE_USER del import.sql porque @DataJpaTest puede
        // tener su propia inicialización; creamos uno local para evitar acoplamiento)
        Role testRole = entityManager.persistAndFlush(new Role("ROLE_TEST"));

        testUser = new User();
        testUser.setEmail("test@example.com");
        testUser.setPasswordHash("$2a$12$dummyhashfordatabasetestpurposesonly");
        testUser.setFirstName("Test");
        testUser.setLastName("User");
        testUser.addRole(testRole);
        testUser = entityManager.persistAndFlush(testUser);
    }

    @Test
    void findValidByTokenHash_returnsToken_whenTokenIsValid() {
        // Given: un token que existe, no está revocado y expira en 1 hora
        RefreshToken token = newToken("valid-hash", Instant.now().plus(1, ChronoUnit.HOURS), null);

        // When: lo buscamos como "válido ahora"
        Optional<RefreshToken> result = refreshTokenRepository.findValidByTokenHash(
                "valid-hash", Instant.now());

        // Then: lo encontramos
        assertThat(result).isPresent();
        assertThat(result.get().getTokenHash()).isEqualTo("valid-hash");
        assertThat(result.get().getUser().getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void findValidByTokenHash_returnsEmpty_whenTokenIsExpired() {
        // Given: un token que ya expiró (hace 1 hora)
        RefreshToken token = newToken("expired-hash", Instant.now().minus(1, ChronoUnit.HOURS), null);

        // When + Then: NO lo encontramos
        Optional<RefreshToken> result = refreshTokenRepository.findValidByTokenHash(
                "expired-hash", Instant.now());
        assertThat(result).isEmpty();
    }

    @Test
    void findValidByTokenHash_returnsEmpty_whenTokenIsRevoked() {
        // Given: un token revocado (logout o rotación)
        RefreshToken token = newToken(
                "revoked-hash",
                Instant.now().plus(1, ChronoUnit.HOURS),
                Instant.now().minus(1, ChronoUnit.MINUTES));

        // When + Then: NO lo encontramos aunque no esté expirado
        Optional<RefreshToken> result = refreshTokenRepository.findValidByTokenHash(
                "revoked-hash", Instant.now());
        assertThat(result).isEmpty();
    }

    @Test
    void findValidByTokenHash_returnsEmpty_whenTokenDoesNotExist() {
        // When + Then: hash desconocido no aparece
        Optional<RefreshToken> result = refreshTokenRepository.findValidByTokenHash(
                "nonexistent-hash", Instant.now());
        assertThat(result).isEmpty();
    }

    // ----- Helper -----

    private RefreshToken newToken(String hash, Instant expiresAt, Instant revokedAt) {
        RefreshToken token = new RefreshToken();
        token.setUser(testUser);
        token.setTokenHash(hash);
        token.setExpiresAt(expiresAt);
        token.setRevokedAt(revokedAt);
        return refreshTokenRepository.saveAndFlush(token);
    }
}
