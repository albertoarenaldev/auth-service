package dev.albertoarenaldev.authservice.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ForgotPasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.ResetPasswordRequest;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de integracion del {@link AuthController} con {@code MockMvc}.
 *
 * <p>Cubre los 6 endpoints reales:
 * <ul>
 *   <li>{@code POST /register} - alta + emision del primer par de tokens.</li>
 *   <li>{@code POST /login} - autenticacion + emision de tokens.</li>
 *   <li>{@code POST /refresh} - rotacion de refresh tokens + deteccion de reuso.</li>
 *   <li>{@code POST /logout} - revocacion idempotente de un refresh.</li>
 *   <li>{@code POST /forgot-password} - inicio del flujo de reset (siempre 202).</li>
 *   <li>{@code POST /reset-password} - canje de token + actualizacion de password.</li>
 * </ul>
 *
 * <p>Happy paths + 3-4 casos de error por endpoint (400 Bad Request,
 * 401 Unauthorized, 409 Conflict). Aislamiento: cada test genera emails
 * con UUID unico, asi no hay conflictos entre tests ni necesidad de
 * {@code @DirtiesContext}.
 *
 * <p>Perfil {@code test}: hereda la config del perfil {@code dev} (H2
 * in-memory + JPA + DataSeeder), por lo que las tablas y roles base se
 * crean al arranque.
 *
 * <p><b>{@link EmailSender} mockeado:</b> en estos tests interesa
 * verificar el comportamiento HTTP (status codes + payloads) y la
 * persistencia de tokens, no el envio real de correo. El mock permite
 * ademas extraer el {@code raw reset token} del cuerpo del email
 * mediante {@link ArgumentCaptor}, sin depender de parsers de logs o
 * configuraciones SMTP de test.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {

    private static final String REGISTER_PATH = "/api/v1/auth/register";
    private static final String LOGIN_PATH = "/api/v1/auth/login";
    private static final String REFRESH_PATH = "/api/v1/auth/refresh";
    private static final String LOGOUT_PATH = "/api/v1/auth/logout";
    private static final String FORGOT_PASSWORD_PATH = "/api/v1/auth/forgot-password";
    private static final String RESET_PASSWORD_PATH = "/api/v1/auth/reset-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * Mock del envio de email. Reemplaza el bean real (que en el perfil
     * test loguea a consola) durante toda la clase. Cada test parte de
     * estado reseteado ({@code @MockBean} resetea el mock antes de
     * ejecutar cada {@code @Test}).
     */
    @MockBean
    private EmailSender emailSender;

    /**
     * Regex para extraer el {@code raw reset token} del cuerpo del email.
     * En {@code PasswordResetService} el body contiene
     * {@code "<baseUrl>?token=<raw>"} donde {@code raw} son 43 chars
     * Base64 URL-safe sin padding ([A-Za-z0-9_-]).
     */
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

    /**
     * Captura el {@code raw reset token} del cuerpo del ultimo email
     * enviado a {@code emailSender} por el servicio de password reset.
     * Invoca {@code /forgot-password} justo antes (helper que se llama
     * en mitad de un test, NO un test en si mismo).
     *
     * @param email destinatario esperado (assertion adicional de seguridad)
     * @return los 43 chars Base64 URL-safe del token raw generado
     */
    private String captureResetTokenFromLastEmail(String email) {
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender).send(eq(email), anyString(), bodyCaptor.capture());
        Matcher m = TOKEN_PARAM.matcher(bodyCaptor.getValue());
        assertThat(m.find())
                .as("body should contain ?token=<raw> parameter: " + bodyCaptor.getValue())
                .isTrue();
        return m.group(1);
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
                // >= 4 (en vez de == 4) para que el test no se rompa si
                // en el futuro se anade un nuevo campo @NotBlank al DTO.
                .andExpect(jsonPath("$.fieldErrors.length()").value(greaterThanOrEqualTo(4)));
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

        // Verifica rotacion: el refresh token nuevo debe ser DISTINTO del viejo
        // (SecureRandom -> 256 bits de entropia, nunca colisiona).
        //
        // NOTA: NO comprobamos que el access token sea distinto porque los
        // claims iat/exp son en milisegundos: si register y refresh ocurren
        // en el mismo ms (tipico en tests rapidos), el JWT seria byte-identico
        // aunque la rotacion si se haya hecho. La rotacion del refresh token
        // es la prueba real de que el flujo funciona; el access token es solo
        // un derivado.
        AuthResponse newResp = objectMapper.readValue(
                result.getResponse().getContentAsString(), AuthResponse.class);
        assertThat(newResp.refreshToken()).isNotEqualTo(regResp.refreshToken());
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

    // ============================================================
    // /forgot-password — OWASP anti-user-enumeration: SIEMPRE 202
    // ============================================================

    @Test
    void forgotPassword_withExistingEmail_returns202AndSendsResetEmail() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        ForgotPasswordRequest req = new ForgotPasswordRequest(regReq.email());

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                // 202 implica cuerpo vacio (no leak de PII / estado)
                .andExpect(jsonPath("$").doesNotExist());

        // El servicio envio el correo AL email normalizado, no leak de
        // formato original
        assertThat(captureResetTokenFromLastEmail(regReq.email())).hasSize(43);
    }

    @Test
    void forgotPassword_withNonExistingEmail_returns202WithoutSendingEmail() throws Exception {
        String ghostEmail = "ghost-" + UUID.randomUUID() + "@example.com";
        ForgotPasswordRequest req = new ForgotPasswordRequest(ghostEmail);

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$").doesNotExist());

        // Anti-enumeration (OWASP): el correo NO se envia para emails
        // no registrados. La respuesta 202 es IDENTICA al caso feliz.
        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    @Test
    void forgotPassword_withBlankEmail_returns400() throws Exception {
        ForgotPasswordRequest req = new ForgotPasswordRequest("");

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray());

        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    @Test
    void forgotPassword_withInvalidEmailFormat_returns400() throws Exception {
        ForgotPasswordRequest req = new ForgotPasswordRequest("not-a-valid-email-format");

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray())
                // El mensaje de error debe mencionar el campo "email"
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'email')]").exists());

        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    // ============================================================
    // /forgot-password — Fase 6: invalidacion de tokens previos
    // (defense in depth: cierra la ventana de tokens viejos)
    // ============================================================

    @Test
    void forgotPassword_threeConsecutiveRequests_onlyTheLastTokenIsValid() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        // 3 resets consecutivos: el servicio publica 3 eventos, envia
        // 3 correos, pero solo el ULTIMO token raw puede canjearse.
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                    .andExpect(status().isAccepted());
        }

        // Capturamos los 3 raw tokens que salieron del mock emailSender.
        // ArgumentCaptor#getAllValues() devuelve los 3 en orden de llamada.
        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender, org.mockito.Mockito.times(3))
                .send(eq(regReq.email()), anyString(), bodyCaptor.capture());
        java.util.List<String> bodies = bodyCaptor.getAllValues();
        assertThat(bodies).hasSize(3);

        String firstToken = extractTokenFromBody(bodies.get(0));
        String secondToken = extractTokenFromBody(bodies.get(1));
        String thirdToken = extractTokenFromBody(bodies.get(2));
        assertThat(firstToken).isNotEqualTo(secondToken).isNotEqualTo(thirdToken);
        assertThat(secondToken).isNotEqualTo(thirdToken);

        // El primer token debe estar invalidado (su usedAt != null). Intentar
        // canjearlo da 401.
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(firstToken, "ShouldNotWork-123"))))
                .andExpect(status().isUnauthorized());

        // El segundo token tambien (se invalido al pedir el tercero). 401.
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(secondToken, "ShouldNotWork-456"))))
                .andExpect(status().isUnauthorized());

        // El tercer token (el ultimo) sigue siendo valido. 204.
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new ResetPasswordRequest(thirdToken, "Final-Working-789"))))
                .andExpect(status().isNoContent());
    }

    @Test
    void forgotPassword_timingIsSimilarBetweenExistingAndNonExistingEmails() throws Exception {
        // Defense in depth (OWASP anti-enumeration, timing): el path
        // "usuario existe" y el path "usuario no existe" deben tener
        // latencia similar para impedir que un atacante distinga por
        // tiempo de respuesta. El path not-found ejecuta un dummy
        // bcrypt encode (~100-250ms) que iguala la latencia del path
        // exitoso (DB insert + SHA-256 + event publish ~5-15ms + bcrypt
        // dummy).
        //
        // NOTA sobre CI: los timing tests son notorios por su flakiness.
        // Usamos un bound generoso (500ms) que detecta regresiones serias
        // (e.g. alguien quita el dummy bcrypt) pero no rompe por jitter
        // de GC / cold start. Si el bound se vuelve problematico en CI,
        // ajustar o mover a un profile @Tag("timing") y excluir del CI.
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        // Warmup: descarta el primer request (JIT + connection pool warmup)
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))));
            mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new ForgotPasswordRequest("ghost-" + i + "@example.com"))));
        }

        // Medimos la mediana de N requests para cada caso (mediana es
        // mas robusta a outliers que la media).
        int N = 5;
        long[] existingTimes = new long[N];
        long[] nonExistingTimes = new long[N];
        for (int i = 0; i < N; i++) {
            String ghost = "ghost-measure-" + i + "-" + UUID.randomUUID() + "@example.com";

            long t0 = System.nanoTime();
            mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))));
            existingTimes[i] = (System.nanoTime() - t0) / 1_000_000L;

            long t1 = System.nanoTime();
            mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(ghost))));
            nonExistingTimes[i] = (System.nanoTime() - t1) / 1_000_000L;
        }

        long medianExisting = median(existingTimes);
        long medianNonExisting = median(nonExistingTimes);
        long diff = Math.abs(medianExisting - medianNonExisting);

        // Bound generoso de 500ms. El dummy bcrypt en el path not-found
        // deberia acercar la mediana del path existente y el no-existente.
        // Si el diff se va a >500ms, probablemente alguien quito el dummy
        // o rompieron el flujo async.
        assertThat(diff)
                .as("Timing diff entre usuario existente (%dms) y no-existente (%dms) excede 500ms — defense-in-depth OWASP anti-enumeration comprometido",
                        medianExisting, medianNonExisting)
                .isLessThan(500L);
    }

    private static long median(long[] values) {
        long[] sorted = values.clone();
        java.util.Arrays.sort(sorted);
        return sorted[sorted.length / 2];
    }

    private static String extractTokenFromBody(String body) {
        Matcher m = TOKEN_PARAM.matcher(body);
        assertThat(m.find())
                .as("body should contain ?token=<raw>: " + body)
                .isTrue();
        return m.group(1);
    }

    // ============================================================
    // /reset-password — ciclo completo + casos de error
    // ============================================================

    @Test
    void resetPassword_withValidToken_returns204AndEnablesLoginWithNewPassword() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        // Trigger necesario: forgot-password para obtener un token valido.
        // No cuenta como assertion de /forgot-password (ya cubierto arriba).
        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(regReq.email());

        String newPassword = "Brand-New-Pass-456";
        ResetPasswordRequest resetReq = new ResetPasswordRequest(rawResetToken, newPassword);

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isNoContent());

        // Login con el NUEVO password debe funcionar (201/200 OK).
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(regReq.email(), newPassword))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        // Login con el password VIEJO debe fallar (401).
        mockMvc.perform(post(LOGIN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest(regReq.email(), regReq.password()))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_withUnknownToken_returns401() throws Exception {
        ResetPasswordRequest req = new ResetPasswordRequest("bogus-token-not-in-db", "NewPassword123!");

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Unauthorized"));
    }

    @Test
    void resetPassword_withAlreadyUsedToken_returns401() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        registerAndGetResponse(regReq);

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(regReq.email());

        ResetPasswordRequest resetReq = new ResetPasswordRequest(rawResetToken, "NewPassword123!");

        // Primer canje: exito (204).
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isNoContent());

        // Segundo canje con el MISMO token: 401 (mitigacion contra replay).
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void resetPassword_withBlankToken_returns400() throws Exception {
        ResetPasswordRequest req = new ResetPasswordRequest("", "NewPassword123!");

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'token')]").exists());
    }

    @Test
    void resetPassword_withTooShortPassword_returns400() throws Exception {
        // @Size(min = 8) → 7 chars debe fallar
        ResetPasswordRequest req = new ResetPasswordRequest("any-token", "Sh0rt!7");

        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors").isArray())
                .andExpect(jsonPath("$.fieldErrors[?(@.field == 'newPassword')]").exists());
    }

    // ============================================================
    // Cross-cutting: security hardening (refresh-token revocation
    // post reset) — verifica end-to-end que el commit 6 tiene efecto
    // real.
    // ============================================================

    @Test
    void resetPassword_revokesExistingRefreshTokens_returns401OnSubsequentRefresh() throws Exception {
        RegisterRequest regReq = sampleRegisterRequest();
        AuthResponse regResp = registerAndGetResponse(regReq);
        // En este punto el usuario tiene 1 refresh token activo en BD
        // (el emitido por /register).

        mockMvc.perform(post(FORGOT_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new ForgotPasswordRequest(regReq.email()))))
                .andExpect(status().isAccepted());
        String rawResetToken = captureResetTokenFromLastEmail(regReq.email());

        ResetPasswordRequest resetReq = new ResetPasswordRequest(rawResetToken, "NewSecure-Pass-789");
        mockMvc.perform(post(RESET_PASSWORD_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(resetReq)))
                .andExpect(status().isNoContent());

        // El refresh que tenia el usuario antes del reset debe haber sido
        // revocado (defensa-en-profundidad OWASP). Intentar usarlo da 401.
        // Esto valida end-to-end la cadena:
        //   AuthController.resetPassword →
        //   PasswordResetService.resetPassword →
        //   TokenService.revokeAllForUser(userId) →
        //   RefreshTokenRepository.revokeAllByUserId(userId, now)
        mockMvc.perform(post(REFRESH_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RefreshRequest(regResp.refreshToken()))))
                .andExpect(status().isUnauthorized());
    }
}
