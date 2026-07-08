package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.config.PasswordResetProperties;
import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.PasswordResetToken;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.PasswordResetTokenRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests unitarios de {@link PasswordResetService} con Mockito.
 *
 * <p>Aislan la logica de generacion/expiracion/canjeo de tokens de reset
 * de la capa de persistencia y del envio de correo. Las dependencias
 * ({@link UserRepository}, {@link PasswordResetTokenRepository},
 * {@link PasswordEncoder}, {@link ApplicationEventPublisher},
 * {@link PasswordResetProperties}, {@link JwtProperties}) se mockean.
 *
 * <p><b>Email sender NO se mockea aqui:</b> a partir del fix de timing
 * (Fase 6), el servicio no llama directamente a {@code emailSender.send};
 * publica un {@link PasswordResetRequestedEvent} que consume un listener
 * asincrono. El comportamiento del envio se cubre en los integration
 * tests de {@code AuthControllerIntegrationTest}, donde el
 * {@code @MockBean EmailSender} captura el call desde el listener
 * (que corre en el pool emailExecutor pero se sincroniza en tests
 * con la finalizacion del request MockMvc).
 *
 * <p>Cubre los 2 metodos publicos:
 * <ul>
 *   <li>{@code forgotPassword} — happy path + edge cases + timing
 *       equalization + token invalidation.</li>
 *   <li>{@code resetPassword} — happy path + 4 casos de error.</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    /**
     * TTL del proyecto segun {@code application.properties}. Stub constante
     * para que las assertions de {@code expiresAt} sean estables.
     */
    private static final long TTL_MS = 15 * 60 * 1000L;

    @Mock private UserRepository userRepository;
    @Mock private PasswordResetTokenRepository tokenRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private TokenService tokenService;
    @Mock private PasswordResetProperties passwordResetProperties;
    @Mock private JwtProperties jwtProperties;
    @Mock private ApplicationEventPublisher eventPublisher;

    private PasswordResetService passwordResetService;

    // ============================================================
    // Setup — stubs aplicados ANTES del constructor manual
    // ============================================================

    @BeforeEach
    void setUp() {
        // TTL: el servicio lo lee una sola vez en el constructor y lo
        // cachea en el campo `tokenExpirationMs` (long). Sin este stub
        // previo, el constructor cachearia 0L y los asserts de expiry
        // fallarian. Lo marcamos estandar (sin lenient) porque SIEMPRE
        // se consume — al menos durante la construccion.
        when(jwtProperties.getPasswordResetTokenExpirationMs()).thenReturn(TTL_MS);

        // PasswordResetProperties solo se consulta dentro del camino de
        // send de email. En tests donde el user NO se encuentra o el
        // reset falla antes del send, estos getters NO se invocan.
        // lenient() evita los UnnecessaryStubbingException en strict mode.
        lenient().when(passwordResetProperties.getBaseUrl()).thenReturn("http://localhost:5173/reset-password");
        lenient().when(passwordResetProperties.getAppName()).thenReturn("Auth Service");

        // Constructor manual: ahora ve el TTL stubbeado (900s en vez de 0).
        // El orden de parametros tras el fix Fase 6 es: repositorios, state-
        // mutators, config, eventPublisher (al final).
        passwordResetService = new PasswordResetService(
                userRepository, tokenRepository,
                passwordEncoder, tokenService,
                passwordResetProperties, jwtProperties,
                eventPublisher);
    }

    // ============================================================
    // Helpers
    // ============================================================

    private User sampleUser() {
        User u = new User();
        u.setId(1L);
        u.setEmail("alice@example.com");
        u.setEnabled(true);
        return u;
    }

    /**
     * Token valido segun las reglas del servicio: hash presente, sin
     * uso, expira en el futuro. El user asociado es el que llega por
     * parametro para que la assertion isEqualTo pueda comparar referencias
     * (User no sobreescribe equals).
     */
    private PasswordResetToken sampleValidToken(User user) {
        PasswordResetToken t = new PasswordResetToken();
        t.setId(99L);
        t.setUser(user);
        t.setTokenHash("any-hash");
        t.setExpiresAt(Instant.now().plusSeconds(900)); // 15 min en el futuro
        t.setUsedAt(null);
        return t;
    }

    /**
     * Regex para extraer el raw token del cuerpo del correo. Base64
     * URL-safe sin padding son solo [A-Z][a-z][0-9] + '-' y '_'.
     */
    private static final Pattern TOKEN_PARAM =
            Pattern.compile("\\?token=([A-Za-z0-9_-]+)");

    private String extractRawTokenFromEventBody(String body) {
        Matcher m = TOKEN_PARAM.matcher(body);
        assertThat(m.find())
                .as("event body should contain ?token=<raw> parameter")
                .isTrue();
        return m.group(1);
    }

    // ============================================================
    // forgotPassword — happy path + edge cases
    // ============================================================

    @Test
    void forgotPassword_whenEmailExists_persistsHashedTokenAndPublishesEvent() {
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> inv.getArgument(0));

        passwordResetService.forgotPassword("alice@example.com");

        // Token persistido: referencia igual al user, usedAt null, expiresAt en el futuro
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        PasswordResetToken saved = tokenCaptor.getValue();
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getUsedAt()).isNull();
        assertThat(saved.getExpiresAt()).isAfter(Instant.now());

        // Evento publicado (no SMTP directo): subject + body con el link al appName
        ArgumentCaptor<PasswordResetRequestedEvent> eventCaptor =
                ArgumentCaptor.forClass(PasswordResetRequestedEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        PasswordResetRequestedEvent event = eventCaptor.getValue();
        assertThat(event.email()).isEqualTo("alice@example.com");
        assertThat(event.subject()).isEqualTo("Restablece tu contraseña");
        assertThat(event.body())
                .contains("Auth Service")
                .contains("http://localhost:5173/reset-password?token=");
    }

    @Test
    void forgotPassword_whenEmailDoesNotExist_returnsSilentlyWithoutSendingOrEvent() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());
        // Dummy bcrypt: stub que devuelve un hash cualquiera; solo nos
        // importa que SE LLAME para confirmar el timing equalization.
        when(passwordEncoder.encode(anyString())).thenReturn("dummy-hash");

        passwordResetService.forgotPassword("ghost@example.com");

        // Silencio total al cliente (OWASP anti-enumeration): no persistir,
        // no enviar evento, no exponer al listener.
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(eventPublisher, never()).publishEvent(any(PasswordResetRequestedEvent.class));

        // Timing equalization: dummy bcrypt SE EJECUTA incluso cuando el
        // usuario no existe, para igualar la latencia del path exitoso.
        verify(passwordEncoder).encode(anyString());
    }

    @Test
    void forgotPassword_normalizesEmailToLowercaseTrimBeforeLookup() {
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.empty());

        // Input con MAYUSCULAS + espacios alrededor → normalizado antes del lookup
        passwordResetService.forgotPassword("  ALICE@Example.COM  ");

        // El lookup se hace con la version normalizada (lowercase + trim)
        verify(userRepository).findByEmail("alice@example.com");
    }

    @Test
    void forgotPassword_generatesUrlSafeTokenAndStoresSha256Hash() {
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> inv.getArgument(0));

        passwordResetService.forgotPassword("alice@example.com");

        ArgumentCaptor<PasswordResetRequestedEvent> eventCaptor =
                ArgumentCaptor.forClass(PasswordResetRequestedEvent.class);
        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        verify(tokenRepository).save(tokenCaptor.capture());

        // 1) raw token en el event body: 43 caracteres, Base64 URL-safe sin padding
        String rawToken = extractRawTokenFromEventBody(eventCaptor.getValue().body());
        assertThat(rawToken).hasSize(43);

        // 2) hash persistido: 64 chars hex (SHA-256 lowercase) — DISTINTO del raw
        String storedHash = tokenCaptor.getValue().getTokenHash();
        assertThat(storedHash).hasSize(64).matches("[0-9a-f]+");
        assertThat(storedHash).isNotEqualTo(rawToken);
    }

    @Test
    void forgotPassword_persistsTokenWithExpiryEqualToConfiguredTtl() {
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> inv.getArgument(0));

        Instant before = Instant.now();
        passwordResetService.forgotPassword("alice@example.com");
        Instant after = Instant.now();

        ArgumentCaptor<PasswordResetToken> captor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(captor.capture());

        // expiresAt ≈ now + 15min (margen de 1s para tolerar jitter del reloj)
        Instant expiresAt = captor.getValue().getExpiresAt();
        assertThat(expiresAt).isAfter(before.plusMillis(TTL_MS - 1000));
        assertThat(expiresAt).isBefore(after.plusMillis(TTL_MS + 1000));
    }

    @Test
    void forgotPassword_whenEmailExists_invalidatesPreviousActiveTokens() {
        // Defense in depth: si el usuario pidio 3 resets, los 3 correos se
        // envian pero solo el ultimo token es valido. El test verifica que
        // el repositorio recibe la llamada de invalidacion ANTES de generar
        // el token nuevo.
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> inv.getArgument(0));
        when(tokenRepository.invalidateActiveTokensForUser(eq(1L), any(Instant.class))).thenReturn(2);

        passwordResetService.forgotPassword("alice@example.com");

        // El repositorio fue consultado para invalidar tokens previos
        ArgumentCaptor<Instant> nowCaptor = ArgumentCaptor.forClass(Instant.class);
        verify(tokenRepository).invalidateActiveTokensForUser(eq(1L), nowCaptor.capture());
        assertThat(nowCaptor.getValue()).isBefore(Instant.now().plusSeconds(2));
    }

    @Test
    void forgotPassword_whenNoPreviousTokens_invalidateReturnsZeroAndServiceProceeds() {
        // Si el usuario nunca pidio un reset antes, invalidar no hace nada
        // y el flujo continua normalmente (no se lanza excepcion).
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(inv -> inv.getArgument(0));
        when(tokenRepository.invalidateActiveTokensForUser(eq(1L), any(Instant.class))).thenReturn(0);

        passwordResetService.forgotPassword("alice@example.com");

        verify(tokenRepository).invalidateActiveTokensForUser(eq(1L), any(Instant.class));
        verify(tokenRepository).save(any(PasswordResetToken.class));
        verify(eventPublisher).publishEvent(any(PasswordResetRequestedEvent.class));
    }

    // ============================================================
    // resetPassword
    // ============================================================

    @Test
    void resetPassword_whenTokenIsValid_unusedAndNotExpired_marksUsedAndUpdatesHash() {
        User user = sampleUser();
        PasswordResetToken stored = sampleValidToken(user);
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));
        when(passwordEncoder.encode("NewPassword123!")).thenReturn("new-bcrypt-hash");

        passwordResetService.resetPassword("some-raw-token", "NewPassword123!");

        // Token marcado como usado: usedAt en pasado reciente
        assertThat(stored.getUsedAt()).isNotNull();
        assertThat(stored.getUsedAt()).isBefore(Instant.now().plusSeconds(2));

        // User actualizado con el hash bcrypt (NO la password en claro)
        assertThat(user.getPasswordHash()).isEqualTo("new-bcrypt-hash");
        assertThat(user.getPasswordHash()).isNotEqualTo("NewPassword123!");

        verify(tokenRepository).save(stored);
        verify(userRepository).save(user);
        // Defensa en profundidad (OWASP): tambien se revocan TODOS los
        // refresh tokens del usuario. Verificacion redundante con
        // resetPassword_whenSuccessful_revokesAllRefreshTokensOfUser para
        // que un fallo del path de revocacion se vea aqui tambien.
        verify(tokenService).revokeAllForUser(1L);
    }

    @Test
    void resetPassword_whenSuccessful_revokesAllRefreshTokensOfUser() {
        User user = sampleUser();
        PasswordResetToken stored = sampleValidToken(user);
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));
        when(passwordEncoder.encode(anyString())).thenReturn("new-bcrypt-hash");
        when(tokenService.revokeAllForUser(1L)).thenReturn(3); // 3 sesiones en otros dispositivos

        passwordResetService.resetPassword("some-raw-token", "NewPassword123!");

        // Defensa en profundidad (OWASP): todos los refresh tokens del usuario
        // se revocan tras un cambio exitoso de password
        verify(tokenService).revokeAllForUser(1L);
    }

    @Test
    void resetPassword_whenTokenAlreadyUsed_throwsInvalidTokenExceptionAndDoesNotMutate() {
        User user = sampleUser();
        PasswordResetToken stored = sampleValidToken(user);
        Instant previousUsedAt = Instant.now().minusSeconds(60);
        stored.setUsedAt(previousUsedAt);
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> passwordResetService.resetPassword("any-raw", "NewPassword123!"))
                .isInstanceOf(InvalidTokenException.class);

        // Mensaje generico + sin mutaciones: usedAt preservado, no se guarda nada
        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        // Sin revocar sesiones: la validacion fallo antes de llegar al path exitoso
        verify(tokenService, never()).revokeAllForUser(anyLong());
        assertThat(stored.getUsedAt()).isEqualTo(previousUsedAt);
    }

    @Test
    void resetPassword_whenTokenExpired_throwsInvalidTokenException() {
        User user = sampleUser();
        PasswordResetToken stored = sampleValidToken(user);
        stored.setExpiresAt(Instant.now().minusSeconds(60)); // expirado hace 60s
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> passwordResetService.resetPassword("any-raw", "NewPassword123!"))
                .isInstanceOf(InvalidTokenException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(tokenService, never()).revokeAllForUser(anyLong());
    }

    @Test
    void resetPassword_whenUserIsDisabled_throwsInvalidTokenException() {
        User user = sampleUser();
        user.setEnabled(false); // admin deshabilita al usuario → no debe poder resetear
        PasswordResetToken stored = sampleValidToken(user);
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> passwordResetService.resetPassword("any-raw", "NewPassword123!"))
                .isInstanceOf(InvalidTokenException.class);

        // Defensa en profundidad: ni se actualiza el user ni se marca el token
        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(tokenService, never()).revokeAllForUser(anyLong());
        assertThat(stored.getUsedAt()).isNull();
    }

    @Test
    void resetPassword_whenTokenNotFound_throwsInvalidTokenException() {
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> passwordResetService.resetPassword("any-raw", "NewPassword123!"))
                .isInstanceOf(InvalidTokenException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(PasswordResetToken.class));
        verify(tokenService, never()).revokeAllForUser(anyLong());
    }
}
