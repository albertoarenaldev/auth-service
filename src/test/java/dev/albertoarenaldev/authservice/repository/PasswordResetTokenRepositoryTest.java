package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.PasswordResetToken;
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
 * Tests del repositorio de tokens de reset de contraseña.
 *
 * <p>Cubre:
 * <ul>
 *   <li>{@code findByTokenHash} — usado en {@code POST /password/reset} para
 *       localizar el token que el usuario presenta</li>
 *   <li>{@code deleteExpiredOrUsed} — job de limpieza que borra tokens viejos</li>
 * </ul>
 */
@DataJpaTest
@ActiveProfiles("test")
class PasswordResetTokenRepositoryTest {

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    private TestEntityManager entityManager;

    private User testUser;

    @BeforeEach
    void setUp() {
        Role role = entityManager.persistAndFlush(new Role("ROLE_TEST"));
        testUser = new User();
        testUser.setEmail("alice@example.com");
        testUser.setPasswordHash("$2a$12$dummyhashfordatabasetestpurposesonly");
        testUser.setFirstName("Alice");
        testUser.setLastName("Tester");
        testUser.addRole(role);
        testUser = entityManager.persistAndFlush(testUser);
    }

    @Test
    void findByTokenHash_returnsToken_whenTokenExists() {
        // Given
        PasswordResetToken token = persistToken("hash-exists", Instant.now().plus(1, ChronoUnit.HOURS), null);

        // When
        Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("hash-exists");

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getTokenHash()).isEqualTo("hash-exists");
    }

    @Test
    void findByTokenHash_returnsEmpty_whenTokenDoesNotExist() {
        Optional<PasswordResetToken> result = passwordResetTokenRepository.findByTokenHash("nonexistent");

        assertThat(result).isEmpty();
    }

    @Test
    void deleteExpiredOrUsed_deletesOnlyExpiredAndUsedTokens() {
        // Given: 3 tokens con distinto estado
        Instant futureExpiry = Instant.now().plus(1, ChronoUnit.HOURS);
        Instant pastExpiry = Instant.now().minus(1, ChronoUnit.HOURS);

        PasswordResetToken valid = persistToken("valid-token", futureExpiry, null);
        PasswordResetToken expired = persistToken("expired-token", pastExpiry, null);
        PasswordResetToken used = persistToken("used-token", futureExpiry, Instant.now().minus(5, ChronoUnit.MINUTES));

        // Sanity check: 3 tokens creados
        assertThat(passwordResetTokenRepository.count()).isEqualTo(3L);

        // When: limpieza
        int deleted = passwordResetTokenRepository.deleteExpiredOrUsed(Instant.now());

        // Then: solo se borran los 2 (expired + used), el válido sobrevive
        assertThat(deleted).isEqualTo(2);
        assertThat(passwordResetTokenRepository.count()).isEqualTo(1L);
        assertThat(passwordResetTokenRepository.findByTokenHash("valid-token")).isPresent();
        assertThat(passwordResetTokenRepository.findByTokenHash("expired-token")).isEmpty();
        assertThat(passwordResetTokenRepository.findByTokenHash("used-token")).isEmpty();
    }

    // ----- Helper -----

    private PasswordResetToken persistToken(String hash, Instant expiresAt, Instant usedAt) {
        PasswordResetToken token = new PasswordResetToken();
        token.setUser(testUser);
        token.setTokenHash(hash);
        token.setExpiresAt(expiresAt);
        token.setUsedAt(usedAt);
        return passwordResetTokenRepository.saveAndFlush(token);
    }
}
