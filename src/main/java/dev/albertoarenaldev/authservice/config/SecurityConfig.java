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
    private final OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;     // nullable (NO siempre existe)
    private final ClientRegistrationRepository clientRegistrationRepository;   // nullable (NO siempre existe)

    public SecurityConfig(JwtAuthenticationEntryPoint authenticationEntryPoint,
                          JwtAuthenticationFilter jwtAuthenticationFilter,
                          ObjectProvider<OAuth2AuthenticationSuccessHandler> oauth2SuccessHandlerProvider,
                          ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        // ObjectProvider.getIfAvailable() devuelve null si el bean no existe.
        // En nuestro caso, el handler está @ConditionalOnBean(ClientRegistrationRepository.class)
        // y OAuth2ClientAutoConfiguration solo crea el repo si hay credenciales.
        // Si no hay nada → ambos son null → app sigue arrancando con JWT nativo.
        this.oauth2SuccessHandler = oauth2SuccessHandlerProvider.getIfAvailable();
        this.clientRegistrationRepository = clientRegistrationRepositoryProvider.getIfAvailable();
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

        // OAuth2 solo si AMBOS existen: handler (creado por @ConditionalOnBean)
        // y ClientRegistrationRepository (creado por OAuth2ClientAutoConfiguration
        // solo si hay credenciales via env vars). Doble guard defensivo.
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
