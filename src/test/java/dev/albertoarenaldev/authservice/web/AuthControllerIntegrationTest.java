package dev.albertoarenaldev.authservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de integracion del {@link AuthController} con {@code MockMvc}.
 *
 * <p>Cubre los 4 endpoints reales (register, login, refresh, logout) en
 * sus happy paths + 3 casos de error (400 Bad Request, 401 Unauthorized,
 * 409 Conflict). Aislamiento: cada test genera emails con UUID unico,
 * asi no hay conflictos entre tests ni necesidad de {@code @DirtiesContext}.
 *
 * <p>Perfil {@code test}: hereda la config del perfil {@code dev} (H2
 * in-memory + JPA + DataSeeder), por lo que las tablas y roles base se
 * crean al arranque.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REFRESH_PATH = "/api/v1/auth/refresh";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    // ============================================================
    // Helpers
    // ============================================================

    private String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private RegisterRequest sampleRegisterRequest() {
        return new RegisterRequest(
                uniqueEmail(),
                "Password123!",
                "Test",
                "User"
        );
    }

    private AuthResponse registerAndGetResponse(RegisterRequest req) throws Exception {
        MvcResult result = mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
    }

    // ============================================================
    // /register
    // ============================================================

    @Test
    void register_withValidData_returns201WithTokens() throws Exception {
        RegisterRequest req = sampleRegisterRequest();

        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.email").value(req.email()))
                .andExpect(jsonPath("$.user.firstName").value("Test"))
                .andExpect(jsonPath("$.user.lastName").value("User"))
                .andExpect(jsonPath("$.user.roles[0]").value("ROLE_USER"));
    }

    @Test
    void register_withDuplicateEmail_returns409() throws Exception {
        RegisterRequest req = sampleRegisterRequest();

        // First registration succeeds.
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        // Second registration with the same email must fail with 409 Conflict.
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Conflict"))
                .andExpect(jsonPath("$.message").value(containsString(req.email())));
    }

    @Test
    void register_withInvalidBody_returns400WithFieldErrors() throws Exception {
        // Empty body: violates @NotBlank on email, password, firstName, lastName.
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors.length()").value(4));
    }

    // ============================================================
    // /login
    // ============================================================

    @Test
    void login_withValidCredentials_returns200WithTokens() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        LoginRequest loginReq = new LoginRequest(regReq.email(), regReq.password());

        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.email").value(regReq.email()));
    }

    @Test
    void login_withInvalidPassword_returns401() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        LoginRequest loginReq = new LoginRequest(regReq.email(), "WrongPassword123!");

        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    // ============================================================
    // /refresh
    // ============================================================

    @Test
    void refresh_withValidToken_returns200WithNewRotatedTokens() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        AuthResponse regResp = registerAndGetResponse(regReq);

        RefreshRequest refreshReq = new RefreshRequest(regResp.refreshToken());

        MvcResult result = mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        // Verifica rotacion: los tokens nuevos deben ser DISTINTOS de los viejos.
        // Esto valida que TokenService.rotateRefreshToken emite tokens nuevos
        // y no devuelve el mismo par.
        AuthResponse newResp = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponse.class);
        assertThat(newResp.refreshToken()).isNotEqualTo(regResp.refreshToken());
        assertThat(newResp.accessToken()).isNotEqualTo(regResp.accessToken());
    }

    // ============================================================
    // /logout
    // ============================================================

    @Test
    void logout_withValidToken_returns204() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        AuthResponse regResp = registerAndGetResponse(regReq);

        RefreshRequest logoutReq = new RefreshRequest(regResp.refreshToken());

        mockMvc.perform(post(LOGOUT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutReq)))
                .andExpect(status().isNoContent());

        // Verifica idempotencia: tras el logout, el token no debe poder
        // usarse para hacer refresh (debe devolver 401).
        mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutReq)))
                .andExpect(status().isUnauthorized());
    }
}
