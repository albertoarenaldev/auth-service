package dev.albertoarenaldev.authservice.security;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;


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

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private String validToken;

    @BeforeEach
    void setUp() {
        // Asegurar que el rol base exista (DataSeeder lo crea, pero por si acaso)
        Role roleUser = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(new Role("ROLE_USER")));

        // Idempotente: si el usuario ya existe (otro @BeforeEach en esta misma
        // clase lo creo), lo reusamos. La BD H2 persiste entre tests dentro de
        // la misma clase (@SpringBootTest con DB_CLOSE_DELAY=-1).
        User testUser = userRepository.findByEmail("alice@example.com")
                .orElseGet(() -> {
                    User u = new User();
                    u.setEmail("alice@example.com");
                    u.setPasswordHash("hashed-password-for-test");
                    u.setFirstName("Alice");
                    u.setLastName("Test");
                    u.setEnabled(true);
                    u.addRole(roleUser);
                    return userRepository.save(u);
                });

        // Regenerar el token: el usuario ya existe en BD (Fase 6),
        // UserController.getCurrentUser lo busca via userRepository.
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
        // El endpoint /api/v1/users/me existe desde Fase 6 (UserController).
        // Con token valido + usuario en BD, debe devolver 200 OK.
        mockMvc.perform(get("/api/v1/users/me")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("alice@example.com"));
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
