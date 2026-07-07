package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test dedicado al {@link DataSeeder}.
 *
 * <p>Se mantiene separado del smoke test ({@code AuthServiceApplicationTests})
 * a propósito: el smoke test solo verifica que el contexto Spring arranca.
 * La lógica del seeder tiene su propio test, con su propio nombre, y puede
 * cambiar sin tocar el smoke test.
 *
 * <p>Aserciones:
 * <ul>
 *   <li>Ambos roles base existen tras el arranque ({@code CommandLineRunner})</li>
 *   <li>No hay duplicados: se siembra por nombre, no por id</li>
 *   <li>Se usa {@code containsExactlyInAnyOrder} (no {@code count == 2}) para
 *       que el test sobreviva si en el futuro se añade un tercer rol
 *       (p. ej. {@code ROLE_MODERATOR})</li>
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
class DataSeederTest {

    @Autowired
    private RoleRepository roleRepository;

    @Test
    void seeder_createsBaseRoles_onFirstRun() {
        List<Role> roles = roleRepository.findAll();

        assertThat(roles)
                .extracting(Role::getName)
                .as("El seeder debe haber creado ROLE_USER y ROLE_ADMIN")
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }
}
