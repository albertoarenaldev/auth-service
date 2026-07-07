package dev.albertoarenaldev.authservice.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifica que el binding de {@code @ConfigurationProperties} funciona
 * con el profile {@code test}. Si los nombres de campos no encajan con
 * las propiedades, este test falla con un mensaje claro al arrancar
 * la app (gracias a {@code @Validated} en {@link JwtProperties}) en
 * vez de un NullPointerException en runtime.
 */
@SpringBootTest
@ActiveProfiles("test")
class JwtPropertiesTest {

    @Autowired
    private JwtProperties jwtProperties;

    @Test
    void binding_picksUpTestProfileValues() {
        assertThat(jwtProperties.getSecret())
                .as("El secret del profile test debe bindear y empezar con 'test-only-secret'")
                .isNotBlank()
                .startsWith("test-only-secret");
        assertThat(jwtProperties.getIssuer())
                .as("El issuer del profile test debe ser 'auth-service-test'")
                .isEqualTo("auth-service-test");
        assertThat(jwtProperties.getAccessTokenExpirationMs())
                .as("accessTokenExpirationMs debe ser positivo")
                .isPositive();
        assertThat(jwtProperties.getRefreshTokenExpirationMs())
                .as("refreshTokenExpirationMs debe ser positivo")
                .isPositive();
        assertThat(jwtProperties.getPasswordResetTokenExpirationMs())
                .as("passwordResetTokenExpirationMs debe ser positivo")
                .isPositive();
    }
}
