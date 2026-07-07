package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Seed inicial — crea los 2 roles base (ROLE_USER, ROLE_ADMIN) si no existen.
 *
 * <p>Se ejecuta al arrancar la app. Es idempotente: si los roles ya existen
 * (porque ya se hizo seed en un run anterior), no hace nada.
 *
 * <p>Reemplaza al antiguo {@code import.sql} para evitar problemas de
 * aislamiento en tests (el SQL init corría en cada contexto de test y la
 * H2 in-memory compartida causaba violaciones de PK en los tests JPA).
 */
@Component
public class DataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final RoleRepository roleRepository;

    public DataSeeder(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    @Transactional
    public void run(String... args) {
        seedRole("ROLE_USER");
        seedRole("ROLE_ADMIN");
    }

    private void seedRole(String name) {
        if (roleRepository.existsByName(name)) {
            return;
        }
        roleRepository.save(new Role(name));
        log.info("Seeded role: {}", name);
    }
}
