package dev.albertoarenaldev.authservice.security;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test de integración del SecurityConfig con MockMvc.
 *
 * <p>Verifica el routing de Spring Security:
 * <ul>
 *   <li>{@code /api/v1/auth/**} es público (200 sin token)</li>
 *   <li>{@code /actuator/health} es público (200 sin token)</li>
 *   <li>Cualquier otro endpoint requiere auth (401 con cuerpo JSON limpio)</li>
 *   <li>Un token válido permite pasar la auth (status != 401)</li>
 *   <li>Un token inválido sigue dando 401 con cuerpo JSON</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider tokenProvider;

    private String validToken;

    @BeforeEach
    void setUp() {
        Role roleUser = new Role("ROLE_USER");
        User testUser = new User();
        testUser.setEmail("alice@example.com");
        testUser.setRoles(Set.of(roleUser));
        validToken = tokenProvider.generateAccessToken(testUser);
    }

    @Test
    void authHealthEndpoint_isPublic_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/auth/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void actuatorHealth_isPublic_returns200() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    void actuatorInfo_isProtected_returns401WithoutToken() throws Exception {
        // /actuator/info puede leakear metadata del build (info.app.name, etc.),
        // por eso va a authenticated() y no a permitAll().
        mockMvc.perform(get("/actuator/info"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpoint_withoutToken_returns401WithJsonBody() throws Exception {
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.error").value("Unauthorized"))
                .andExpect(jsonPath("$.path").value("/api/v1/users/me"));
    }

    @Test
    void protectedEndpoint_withValidToken_doesNotReturn401() throws Exception {
        // El endpoint /api/v1/users/me no existe todavía (sin controller),
        // pero la auth debe pasar. Devuelve 404 (no encontrado) en vez de 401.
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status)
                            .as("Con token válido, el endpoint no debe devolver 401 (la auth pasó)")
                            .isNotEqualTo(401);
                });
    }

    @Test
    void protectedEndpoint_withInvalidToken_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer not.a.valid.jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void unauthorizedResponse_includesBearerAuthenticateHeader() throws Exception {
        // RFC 6750: cualquier 401 en una API con Bearer debe llevar el header
        // WWW-Authenticate para que clientes/proxies detecten el esquema.
        mockMvc.perform(get("/api/v1/users/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists("WWW-Authenticate"))
                .andExpect(header().string("WWW-Authenticate", containsString("Bearer")));
    }
}
