package dev.albertoarenaldev.authservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test — verifica que el contexto Spring arranca correctamente y que
 * JPA / Hibernate / repositorios están bien configurados.
 *
 * <p>Si este test pasa, sabemos que:
 * <ul>
 *   <li>El {@code @SpringBootApplication} se carga sin errores</li>
 *   <li>Las 4 entidades se mapean a tablas sin conflictos</li>
 *   <li>Las dependencias (security, jjwt, mail, actuator) están bien inyectadas</li>
 *   <li>El perfil {@code dev} (H2 + import.sql) funciona</li>
 * </ul>
 *
 * <p>Si falla, el problema está en la base del proyecto (entidades, configs, deps).
 */
@SpringBootTest
@ActiveProfiles("dev")
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
        // Si el contexto no arranca, este test falla. No hace falta assert.
    }
}
