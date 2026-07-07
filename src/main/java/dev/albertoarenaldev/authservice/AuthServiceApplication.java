package dev.albertoarenaldev.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for the Auth Service.
 *
 * <p>Stack: Spring Boot 3.5.5 + Spring Security + JPA + JJWT 0.12.5.
 * Perfiles: dev (H2 + MailHog) / prod (PostgreSQL + SMTP real).
 *
 * <p>{@link ConfigurationPropertiesScan} registra automáticamente todos
 * los beans {@code @ConfigurationProperties} del paquete {@code security}
 * (p. ej. {@code JwtProperties}).
 */
@SpringBootApplication
@ConfigurationPropertiesScan("dev.albertoarenaldev.authservice.security")
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
