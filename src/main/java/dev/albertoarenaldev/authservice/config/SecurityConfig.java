package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.security.JwtAuthenticationEntryPoint;
import dev.albertoarenaldev.authservice.security.JwtAuthenticationFilter;
import dev.albertoarenaldev.authservice.security.OAuth2AuthenticationSuccessHandler;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * Configuración de Spring Security: API stateless con JWT.
 *
 * <p>Reglas de autorización:
 * <ul>
 *   <li>{@code /api/v1/auth/**} — público (register, login, refresh, health,
 *       forgot-password, reset-password — todos sin autenticación previa)</li>
 *   <li>{@code /actuator/health} — público (load balancers, monitoring)</li>
 *   <li>{@code /actuator/info} — protegido (puede leakear metadata del build)</li>
 *   <li>Resto — requiere JWT válido en el header {@code Authorization}</li>
 * </ul>
 *
 * <p>CSRF deshabilitado (la API es stateless, no usa cookies de sesión).
 * Sesiones stateless. CORS configurable vía {@code app.cors.origins} (CSV).
 * El filtro JWT se inserta antes de {@code UsernamePasswordAuthenticationFilter}.
 *
 * <p>{@link EnableConfigurationProperties} registra el bean
 * {@link PasswordResetProperties} (prefijo {@code app.password-reset.*}).
 * Es complementario al {@code @ConfigurationPropertiesScan} del main
 * application class, que solo escanea el paquete {@code security}.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({PasswordResetProperties.class, OAuth2Properties.class})
public class SecurityConfig {

    private final JwtAuthenticationEntryPoint authenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // ObjectProviders en vez de beans resueltos: la auto-configuración de OAuth2
    // (OAuth2ClientAutoConfiguration) se ejecuta DESPUÉS de este constructor.
    // Si llamamos getIfAvailable() aquí, siempre devuelve null porque el bean
    // ClientRegistrationRepository aún no existe. Diferimos la resolución al
    // método securityFilterChain(), cuando todos los beans ya están creados.
    private final ObjectProvider<OAuth2AuthenticationSuccessHandler> oauth2SuccessHandlerProvider;
    private final ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider;

    public SecurityConfig(JwtAuthenticationEntryPoint authenticationEntryPoint,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          ObjectProvider<OAuth2AuthenticationSuccessHandler> oauth2SuccessHandlerProvider,
                          ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.oauth2SuccessHandlerProvider = oauth2SuccessHandlerProvider;
        this.clientRegistrationRepositoryProvider = clientRegistrationRepositoryProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(authenticationEntryPoint))
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/v1/auth/**", "/actuator/health").permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // OAuth2 solo si AMBOS existen: handler (@Component sin condiciones,
        // siempre creado) y ClientRegistrationRepository (creado por
        // OAuth2ClientAutoConfiguration porque application.properties tiene
        // registros con centinela NONE).
        // IMPORTANTE: getIfAvailable() debe llamarse AQUÍ, no en el constructor.
        // OAuth2ClientAutoConfiguration se ejecuta después y los beans no existen
        // durante la construcción de esta clase.
        OAuth2AuthenticationSuccessHandler oauth2SuccessHandler = oauth2SuccessHandlerProvider.getIfAvailable();
        ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepositoryProvider.getIfAvailable();

        if (oauth2SuccessHandler != null && clientRegistrationRepository != null) {
            http.oauth2Login(oauth2 -> oauth2.successHandler(oauth2SuccessHandler));
        }

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.origins}") String corsOrigins) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.stream(corsOrigins.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
