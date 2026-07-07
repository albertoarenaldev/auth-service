package dev.albertoarenaldev.authservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test — verifica que el contexto Spring arranca correctamente:
 * <ul>
 *   <li>Las 4 entidades se mapean a tablas sin conflictos</li>
 *   <li>Las dependencias (security, jjwt, mail, actuator) están bien inyectadas</li>
 *   <li>El perfil {@code test} (H2 con UUID aleatorio) funciona</li>
 * </ul>
 *
 * <p>La verificación de la lógica del {@code DataSeeder} vive en
 * {@code DataSeederTest}, en su propio archivo, a propósito: un smoke test
 * solo debe validar el wiring de Spring. Si el seeder se renombra o se
 * refactoriza, el smoke test no debe romperse.
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
        // El contexto Spring arranca sin errores
    }
}
