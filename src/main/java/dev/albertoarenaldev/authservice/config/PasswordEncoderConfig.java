package dev.albertoarenaldev.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * BCrypt con strength 12 (default de Spring Security 6).
 *
 * <p>12 es un buen balance seguridad/CPU: ~250ms por hash en hardware
 * moderno. Si en el futuro la CPU lo permite, subir a 14 (+50% tiempo)
 * sin impacto perceptible al usuario.
 */
@Configuration
public class PasswordEncoderConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
