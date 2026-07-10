package dev.albertoarenaldev.authservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ForgotPasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.ResetPasswordRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.service.email.EmailSender;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de integracion del {@link AuthController} con {@code MockMvc}.
 *
 * <p>Cubre los endpoints de auth + verify-email. Cada test genera
 * emails con UUID unico para evitar conflictos entre tests.
 *
 * <p>Perfil {@code test}: H2 in-memory aislada + DataSeeder.
 *
 * <p>{@link EmailSender} mockeado: permite extraer el raw token
 * del cuerpo del email sin depender de SMTP real.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REFRESH_PATH = "/api/v1/auth/refresh";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";
    private static final String VERIFY_EMAIL_PATH = "/api/v1/auth/verify-email";
    private static final String FORGOT_PASSWORD_PATH = "/api/v1/auth/forgot-password";
    private static final String RESET_PASSWORD_PATH = "/api/v1/auth/reset-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private EmailSender emailSender;

    private static final Pattern TOKEN_PARAM =
            Pattern.compile("\\?token=([A-Za-z0-9_-]+)");

    // ============================================================
    // Helpers
    // ============================================================

    private String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private RegisterRequest sampleRegisterRequest() {
        return new RegisterRequest(
                uniqueEmail(),
                "correct horse battery staple",
                "Test",
                "User"
        );
    }

    /**
     * Registra, extrae el token de verificacion del email, y llama a
     * verify-email para habilitar la cuenta y obtener tokens.
     */
    private AuthResponse registerVerifyAndGetAuth() throws Exception {
        RegisterRequest req = sampleRegisterRequest();

        // 1. Registrar: 201 + UserResponse (sin tokens)
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        // 2. Capturar el token de verificacion del email
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender).send(eq(req.email()), anyString(), bodyCaptor.capture());
        String rawToken = extractTokenFromBody(bodyCaptor.getValue());

        // 3. Verificar email: 200 + AuthResponse con tokens
        MvcResult result = mockMvc.perform(get(VERIFY_EMAIL_PATH)
                        .param("token", rawToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andReturn();

        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
    }

    /** Captura el raw token del ULTIMO email enviado. */
    private String captureResetTokenFromLastEmail(String email) {
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender, org.mockito.Mockito.atLeastOnce())
                .send(eq(email), anyString(), bodyCaptor.capture());
        java.util.List<String> bodies = bodyCaptor.getAllValues();
        return extractTokenFromBody(bodies.get(bodies.size() - 1));
    }

    private static String extractTokenFromBody(String body) {
        Matcher m = TOKEN_PARAM.matcher(body);
        assertThat(m.find())
                .as("body should contain ?token=<raw>: " + body)
                .isTrue();
        return m.group(1);
    }

    private static long median(long[] values) {
        long[] sorted = values.clone();
        java.util.Arrays.sort(sorted);
        return sorted[sorted.length / 2];
    }

    // ============================================================
    // /register
    // ============================================================

    @Test
    void register_withValidData_returns201WithUserResponseAndSendsEmail() throws Exception {
        RegisterRequest req = sampleRegisterRequest();

        MvcResult result = mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated())
                .andReturn();

        UserResponse user = objectMapper.readValue(
                result.getResponse().getContentAsString(), UserResponse.class);
        assertThat(user.email()).isEqualTo(req.email());
        assertThat(user.firstName()).isEqualTo("Test");
        assertThat(user.roles()).containsExactly("ROLE_USER");

        // Se envio el email de verificacion
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender).send(eq(req.email()), anyString(), bodyCaptor.capture());
        assertThat(extractTokenFromBody(bodyCaptor.getValue())).hasSize(43);
    }

    @Test
    void register_withDuplicateEmail_returns409() throws Exception {
        RegisterRequest req = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Conflict"));
    }

    @Test
    void register_withInvalidBody_returns400WithFieldErrors() throws Exception {
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors.length()").value(greaterThanOrEqualTo(4)));
    }

    @Test
    void register_withWeakPassword_returns400() throws Exception {
        RegisterRequest req = new RegisterRequest(uniqueEmail(), "password123", "Test", "User");
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'password')]").exists());
    }

    @Test
    void register_withStrongPassword_returns201() throws Exception {
        RegisterRequest req = new RegisterRequest(
                uniqueEmail(), "correct horse battery staple", "Test", "User");
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());
    }

    // ============================================================
    // /verify-email
    // ============================================================

    @Test
    void verifyEmail_withValidToken_returns200WithTokens() throws Exception {
        AuthResponse auth = registerVerifyAndGetAuth();
        assertThat(auth.accessToken()).isNotEmpty();
        assertThat(auth.refreshToken()).isNotEmpty();
        assertThat(auth.user().email()).isNotEmpty();
    }

    @Test
    void verifyEmail_withUnknownToken_returns401() throws Exception {
        mockMvc.perform(get(VERIFY_EMAIL_PATH)
                        .param("token", "bogus-token-not-in-db"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void verifyEmail_withAlreadyUsedToken_returns401() throws Exception {
        RegisterRequest req = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        String rawToken = captureResetTokenFromLastEmail(req.email());

        // Primer canje: exito
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", rawToken))
                .andExpect(status().isOk());

        // Segundo canje: 401 (token ya usado)
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", rawToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_withoutVerification_returns401() throws Exception {
        RegisterRequest req = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isCreated());

        // Login sin verificar email: 401
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(req.email(), req.password()))))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================
    // /login (con usuario verificado)
    // ============================================================

    @Test
    void login_withValidCredentials_returns200WithTokens() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regReq)))
                .andExpect(status().isCreated());

        // Verificar email primero
        String verifyToken = captureResetTokenFromLastEmail(regReq.email());
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", verifyToken))
                .andExpect(status().isOk());

        // Ahora login funciona
        LoginRequest loginReq = new LoginRequest(regReq.email(), regReq.password());
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty());
    }

    @Test
    void login_withInvalidPassword_returns401() throws Exception {
        AuthResponse auth = registerVerifyAndGetAuth();

        LoginRequest loginReq = new LoginRequest(auth.user().email(), "WrongPassword123!");
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================
    // /refresh
    // ============================================================

    @Test
    void refresh_withValidToken_returns200WithNewRotatedTokens() throws Exception {
        AuthResponse auth = registerVerifyAndGetAuth();

        RefreshRequest refreshReq = new RefreshRequest(auth.refreshToken());
        MvcResult result = mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andReturn();

        AuthResponse newResp = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponse.class);
        assertThat(newResp.refreshToken()).isNotEqualTo(auth.refreshToken());
    }

    // ============================================================
    // /logout
    // ============================================================

    @Test
    void logout_withValidToken_returns204() throws Exception {
        AuthResponse auth = registerVerifyAndGetAuth();

        RefreshRequest logoutReq = new RefreshRequest(auth.refreshToken());
        mockMvc.perform(post(LOGOUT_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutReq)))
                .andExpect(status().isNoContent());

        // El refresh ya no debe funcionar
        mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(logoutReq)))
                .andExpect(status().isUnauthorized());
    }

    // ============================================================
    // /forgot-password
    // ============================================================

    @Test
    void forgotPassword_withExistingEmail_returns202AndSendsResetEmail() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regReq)))
                .andExpect(status().isCreated());
        // Verificar email (necesario? forgot-password funciona con o sin verificacion)
        String verifyToken = captureResetTokenFromLastEmail(regReq.email());
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", verifyToken))
                .andExpect(status().isOk());

        ForgotPasswordRequest req = new ForgotPasswordRequest(regReq.email());
        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted());

        assertThat(captureResetTokenFromLastEmail(regReq.email())).hasSize(43);
    }

    @Test
    void forgotPassword_withNonExistingEmail_returns202WithoutSendingEmail() throws Exception {
        String ghostEmail = "ghost-" + UUID.randomUUID() + "@example.com";
        ForgotPasswordRequest req = new ForgotPasswordRequest(ghostEmail);

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted());

        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    @Test
    void forgotPassword_withBlankEmail_returns400() throws Exception {
        ForgotPasswordRequest req = new ForgotPasswordRequest("");
        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    // ============================================================
    // /reset-password
    // ============================================================

    @Test
    void resetPassword_withValidToken_returns204AndEnablesLoginWithNewPassword() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regReq)))
                .andExpect(status().isCreated());
        String verifyToken = captureResetTokenFromLastEmail(regReq.email());
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", verifyToken))
                .andExpect(status().isOk());

        // forgot-password
        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(regReq.email());

        // reset-password
        String newPassword = "Brand-New-Pass-456";
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(rawResetToken, newPassword))))
                .andExpect(status().isNoContent());

        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(regReq.email(), newPassword))))
                .andExpect(status().isOk());

        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(regReq.email(), regReq.password()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_withUnknownToken_returns401() throws Exception {
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest("bogus-token", "NewPassword123!"))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_withAlreadyUsedToken_returns401() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        mockMvc.perform(post(REGISTER_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(regReq)))
                .andExpect(status().isCreated());
        String verifyToken = captureResetTokenFromLastEmail(regReq.email());
        mockMvc.perform(get(VERIFY_EMAIL_PATH).param("token", verifyToken))
                .andExpect(status().isOk());

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(regReq.email());

        ResetPasswordRequest resetReq = new ResetPasswordRequest(rawResetToken, "NewPassword123!");
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isNoContent());

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_revokesExistingRefreshTokens_returns401OnSubsequentRefresh() throws Exception {
        AuthResponse auth = registerVerifyAndGetAuth();

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(auth.user().email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(auth.user().email());

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(rawResetToken, "NewSecure-Pass-789"))))
                .andExpect(status().isNoContent());

        mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(auth.refreshToken()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_withBlankToken_returns400() throws Exception {
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest("", "NewPassword123!"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'token')]").exists());
    }
}
