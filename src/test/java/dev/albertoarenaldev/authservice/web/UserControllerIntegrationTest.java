package dev.albertoarenaldev.authservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ChangePasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.UpdateProfileRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de integracion del {@link UserController} con {@code MockMvc}.
 *
 * <p>Cubre los 3 endpoints protegidos de Fase 6:
 * <ul>
 *   <li>{@code GET /api/v1/users/me} — perfil del usuario autenticado.</li>
 *   <li>{@code PUT /api/v1/users/me} — actualizar nombre y apellido.</li>
 *   <li>{@code POST /api/v1/users/me/password} — cambio de contraseña
 *       con verificacion de la actual + revocacion de sesiones.</li>
 * </ul>
 *
 * <p>Todos los tests autentican primero (registro + login) y luego usan
 * el access token JWT en el header {@code Authorization: Bearer XXX}.
 * Se cubre tanto el happy path como los casos de error (401 sin token,
 * 400 Bean Validation, 401 password actual incorrecta).
 *
 * <p>Perfil {@code test}: H2 in-memory aislada por UUID, DataSeeder
 * crea ROLE_USER y ROLE_ADMIN al arranque del contexto.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class UserControllerIntegrationTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String ME_PATH = "/api/v1/users/me";
    private static final String ME_PASSWORD_PATH = "/api/v1/users/me/password";

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
                "correct horse battery staple",  // XKCD #936, zxcvbn score 4
                "Test",
                "User"
        );
    }

    /**
     * Registra un usuario y devuelve el AuthResponse con el access token.
     * Helper reutilizado por todos los tests para autenticarse.
     */
    private AuthResponse registerAndGetAuth() throws Exception {
        RegisterRequest req = sampleRegisterRequest();
        MvcResult result = mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
    }

    /**
     * Ejecuta una peticion autenticada con el access token JWT.
     */
    private MvcResult authenticatedGet(String accessToken, String path) throws Exception {
        return mockMvc.perform(get(path)
                        .header("Authorization", "Bearer " + accessToken))
                .andReturn();
    }

    // ============================================================
    // GET /me — perfil del usuario autenticado
    // ============================================================

    @Test
    void getCurrentUser_withValidToken_returns200WithUserProfile() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        mockMvc.perform(get(ME_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.email").value(auth.user().email()))
                .andExpect(jsonPath("$.firstName").value("Test"))
                .andExpect(jsonPath("$.lastName").value("User"))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    void getCurrentUser_withoutToken_returns401() throws Exception {
        mockMvc.perform(get(ME_PATH))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void getCurrentUser_withInvalidToken_returns401() throws Exception {
        mockMvc.perform(get(ME_PATH)
                        .header("Authorization", "Bearer not.a.real.jwt"))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================
    // PUT /me — actualizar nombre y apellido
    // ============================================================

    @Test
    void updateProfile_withValidData_returns200WithUpdatedProfile() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        UpdateProfileRequest updateReq = new UpdateProfileRequest("Bob", "Smith");

        mockMvc.perform(put(ME_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Bob"))
                .andExpect(jsonPath("$.lastName").value("Smith"))
                .andExpect(jsonPath("$.email").value(auth.user().email()))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));

        // Verifica que el cambio persiste (GET /me devuelve los nuevos valores)
        mockMvc.perform(get(ME_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.firstName").value("Bob"))
                .andExpect(jsonPath("$.lastName").value("Smith"));
    }

    @Test
    void updateProfile_withoutToken_returns401() throws Exception {
        UpdateProfileRequest updateReq = new UpdateProfileRequest("Bob", "Smith");

        mockMvc.perform(put(ME_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateProfile_withBlankFields_returns400WithFieldErrors() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        // firstName vacio y lastName vacio → 2 field errors
        UpdateProfileRequest updateReq = new UpdateProfileRequest("", "");

        mockMvc.perform(put(ME_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateReq)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Bad Request"))
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors.length()").value(greaterThanOrEqualTo(2)));
    }

    // ============================================================
    // POST /me/password — cambio de contraseña
    // ============================================================

    @Test
    void changePassword_withCorrectCurrentPassword_returns204AndEnablesLoginWithNewPassword() throws Exception {
        AuthResponse auth = registerAndGetAuth();
        String email = auth.user().email();

        String newPassword = "Brand-New-Passphrase-789";
        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "correct horse battery staple",  // contraseña del register
                newPassword
        );

        // Cambio exitoso → 204 No Content
        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isNoContent());

        // Login con la nueva contraseña debe funcionar
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(email, newPassword))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        // Login con la contraseña vieja debe fallar
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(email, "correct horse battery staple"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_revokesExistingRefreshTokens() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "correct horse battery staple",
                "Brand-New-Passphrase-789"
        );

        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isNoContent());

        // El refresh token original debe estar revocado (OWASP ASVS V3.5)
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + auth.refreshToken() + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_withWrongCurrentPassword_returns401() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "wrong-current-password",
                "Brand-New-Passphrase-789"
        );

        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));

        // La contraseña vieja debe seguir funcionando (no hubo cambio)
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(auth.user().email(), "correct horse battery staple"))))
                .andExpect(status().isOk());
    }

    @Test
    void changePassword_withoutToken_returns401() throws Exception {
        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "old-pass", "NewStrongPass-123");

        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_withWeakNewPassword_returns400() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        // "password123" tiene score zxcvbn = 0 → @StrongPassword lo bloquea
        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "correct horse battery staple",
                "password123"
        );

        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'newPassword')]").exists());
    }

    @Test
    void changePassword_withTooShortNewPassword_returns400() throws Exception {
        AuthResponse auth = registerAndGetAuth();

        // 7 chars → viola @Size(min = 8)
        ChangePasswordRequest changeReq = new ChangePasswordRequest(
                "correct horse battery staple",
                "Sh0rt!7"
        );

        mockMvc.perform(post(ME_PASSWORD_PATH)
                        .header("Authorization", "Bearer " + auth.accessToken())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(changeReq)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'newPassword')]").exists());
    }
}
