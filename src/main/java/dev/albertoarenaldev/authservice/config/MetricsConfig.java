package dev.albertoarenaldev.authservice.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuracion de metricas personalizadas expuestas via Prometheus.
 *
 * <p>Expone contadores y timers para los eventos clave del auth-service:
 * logins (success/failure), registros, verificaciones, password resets,
 * refreshes de token y detecciones de reuso.
 *
 * <p>Accesibles en {@code GET /actuator/prometheus} (sin proteccion
 * adicional: en produccion, proteger este endpoint con autenticacion
 * basica o IP whitelist).
 */
@Configuration
public class MetricsConfig {

    @Bean
    public Counter loginSuccessCounter(MeterRegistry registry) {
        return Counter.builder("auth.login.success")
                .description("Successful login attempts")
                .register(registry);
    }

    @Bean
    public Counter loginFailureCounter(MeterRegistry registry) {
        return Counter.builder("auth.login.failure")
                .description("Failed login attempts")
                .register(registry);
    }

    @Bean
    public Counter registerCounter(MeterRegistry registry) {
        return Counter.builder("auth.register")
                .description("New user registrations")
                .register(registry);
    }

    @Bean
    public Counter emailVerifiedCounter(MeterRegistry registry) {
        return Counter.builder("auth.email.verified")
                .description("Email verifications completed")
                .register(registry);
    }

    @Bean
    public Counter passwordResetRequestedCounter(MeterRegistry registry) {
        return Counter.builder("auth.password.reset.requested")
                .description("Password reset requests")
                .register(registry);
    }

    @Bean
    public Counter passwordResetCompletedCounter(MeterRegistry registry) {
        return Counter.builder("auth.password.reset.completed")
                .description("Password resets completed")
                .register(registry);
    }

    @Bean
    public Counter tokenRefreshCounter(MeterRegistry registry) {
        return Counter.builder("auth.token.refresh")
                .description("Token refresh operations")
                .register(registry);
    }

    @Bean
    public Counter tokenReuseCounter(MeterRegistry registry) {
        return Counter.builder("auth.token.reuse.detected")
                .description("Token reuse detected (potential theft)")
                .register(registry);
    }
}
