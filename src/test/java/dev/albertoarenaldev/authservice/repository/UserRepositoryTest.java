package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests del repositorio de usuarios.
 *
 * <p>Cubre los métodos derivados del nombre (Spring Data los implementa
 * automáticamente) que se usan en el flujo de auth:
 * <ul>
 *   <li>{@code findByEmail} — usado en login y refresh para cargar el User</li>
 *   <li>{@code existsByEmail} — usado en register para evitar duplicados</li>
 * </ul>
 */
@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TestEntityManager entityManager;

    private User persistedUser;

    @BeforeEach
    void setUp() {
        Role role = entityManager.persistAndFlush(new Role("ROLE_TEST"));

        User user = new User();
        user.setEmail("alice@example.com");
        user.setPasswordHash("$2a$12$dummyhashfordatabasetestpurposesonly");
        user.setFirstName("Alice");
        user.setLastName("Tester");
        user.addRole(role);
        persistedUser = entityManager.persistAndFlush(user);
    }

    @Test
    void findByEmail_returnsUser_whenEmailExists() {
        Optional<User> result = userRepository.findByEmail("alice@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(persistedUser.getId());
        assertThat(result.get().getFirstName()).isEqualTo("Alice");
        assertThat(result.get().getRoles())
                .as("Roles deben cargarse en EAGER para el flujo de auth")
                .extracting(Role::getName)
                .containsExactly("ROLE_TEST");
    }

    @Test
    void findByEmail_returnsEmpty_whenEmailDoesNotExist() {
        Optional<User> result = userRepository.findByEmail("bob@nowhere.com");

        assertThat(result).isEmpty();
    }

    @Test
    void existsByEmail_returnsTrue_whenEmailExists() {
        assertThat(userRepository.existsByEmail("alice@example.com")).isTrue();
    }

    @Test
    void existsByEmail_returnsFalse_whenEmailDoesNotExist() {
        assertThat(userRepository.existsByEmail("ghost@nowhere.com")).isFalse();
    }
}
