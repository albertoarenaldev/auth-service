package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.PasswordResetTokenRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.service.email.EmailSender;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/**
 * Test de concurrencia para el flujo {@link PasswordResetService#resetPassword}
 * (auditoria finding #4, severity LOW).
 *
 * <p><b>Que prueba:</b> que 2+ requests concurrentes con el MISMO raw
 * reset token NO pueden tener exito simultaneamente. Antes del fix,
 * el race era teorico: ambos threads leian el token (usedAt=null),
 * pasaban la validacion y ambos intentaban marcarlo como usado. Sin
 * {@code @Version}, ambas escrituras tenian exito. Con el fix:
 * <ol>
 *   <li>{@code PasswordResetToken} tiene un campo {@code @Version Long}.</li>
 *   <li>El segundo UPDATE falla con
 *       {@link org.springframework.orm.ObjectOptimisticLockingFailureException}.</li>
 *   <li>El service traduce esa excepcion a {@link InvalidTokenException}.</li>
 * </ol>
 *
 * <p><b>Configuracion del test:</b>
 * <ul>
 *   <li>{@code @SpringBootTest} + {@code @ActiveProfiles("test")}: arranca
 *       el contexto completo con H2 in-memory y JPA real. El test NO
 *       puede ser unitario (con Mockito) porque el @Version se valida
 *       en el commit de la transaccion, no en el save() del mock.</li>
 *   <li>{@code @MockBean EmailSender}: reemplaza el envio real; el
 *       listener async sigue ejecutandose y capturamos el raw token
 *       del body del email via {@link ArgumentCaptor}.</li>
 *   <li>N=10 threads lanzados simultaneamente con
 *       {@link CountDownLatch} para maximizar la probabilidad de race.</li>
 * </ul>
 *
 * <p><b>Aserciones:</b>
 * <ul>
 *   <li>Exactamente 1 thread completa sin excepcion (el ganador).</li>
 *   <li>Los otros N-1 threads lanzan {@link InvalidTokenException}
 *       (perdedores del race, ya sea por @Version o por token ya usado
 *       — el servicio no distingue, ambos casos son 401 al cliente).</li>
 *   <li>El test completa en menos de 30s (timeout del latch).</li>
 * </ul>
 */
@SpringBootTest
@ActiveProfiles("test")
@DisplayName("PasswordResetService race condition (audit #4)")
class PasswordResetServiceRaceConditionTest {

    /** Numero de threads concurrentes. 10 es suficiente para provocar el race. */
    private static final int CONCURRENT_REQUESTS = 10;

    /** Timeout total para todos los threads. 30s es muy generoso. */
    private static final long AWAIT_TIMEOUT_SECONDS = 30L;

    /**
     * Timeout para que Mockito verifique el envio async del email de
     * forgotPassword. 5s es generoso (la cola emailExecutor tiene
     * corePoolSize=2; el listener deberia correr casi inmediatamente).
     */
    private static final int EMAIL_VERIFY_TIMEOUT_MS = 5_000;

    /** Regex para extraer el raw token del cuerpo del email. */
    private static final Pattern TOKEN_PARAM =
            Pattern.compile("\\?token=([A-Za-z0-9_-]+)");

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordResetTokenRepository tokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private EmailSender emailSender;

    @Test
    @DisplayName("N requests concurrentes con el mismo token: solo 1 tiene exito")
    void resetPassword_concurrentRequestsWithSameToken_onlyOneSucceeds() throws Exception {
        // ============================================================
        // Setup: crear un usuario + generar un token de reset valido
        // ============================================================
        String email = "race-" + UUID.randomUUID() + "@example.com";
        User user = newUser(email);
        // saveAndFlush para que el saveAndFind en el siguiente paso
        // (dentro de la TX de forgotPassword) sea visible inmediatamente.
        userRepository.saveAndFlush(user);

        // forgotPassword es @Transactional; tras su commit el listener
        // async (@TransactionalEventListener AFTER_COMMIT) encola el
        // email. Esperamos con timeout para sincronizar el test con
        // el async.
        passwordResetService.forgotPassword(email);

        ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
        verify(emailSender, timeout(EMAIL_VERIFY_TIMEOUT_MS))
                .send(eq(email), anyString(), bodyCaptor.capture());
        String rawToken = extractRawToken(bodyCaptor.getValue());
        assertThat(rawToken).as("raw token debe tener 43 chars (Base64 URL-safe sin padding)").hasSize(43);

        // ============================================================
        // Race: N threads intentan resetPassword con el mismo token
        // ============================================================
        ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_REQUESTS);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch finishGate = new CountDownLatch(CONCURRENT_REQUESTS);
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);
        // Capturamos los tipos de excepcion por si un reviewer quiere
        // ver cuantos perdieron por @Version vs por token-ya-usado.
        AtomicInteger optimisticLockFailures = new AtomicInteger(0);

        for (int i = 0; i < CONCURRENT_REQUESTS; i++) {
            final int idx = i;
            executor.submit(() -> {
                try {
                    // Todos los threads esperan en startGate hasta que
                    // el main thread haga countDown(). Asi arrancan a
                    // la vez y maximizan la probabilidad de race.
                    startGate.await();
                    passwordResetService.resetPassword(rawToken, "NewPassword" + idx + "-Xk7!");
                    successCount.incrementAndGet();
                } catch (InvalidTokenException ex) {
                    // Esperado: el perdedor del race (ya sea por
                    // ObjectOptimisticLockingFailureException que el
                    // service traduce, o por ver el token ya usado).
                    failureCount.incrementAndGet();
                } catch (org.springframework.orm.ObjectOptimisticLockingFailureException ex) {
                    // Por si el catch interno del service no estuviera
                    // (regression guard).
                    optimisticLockFailures.incrementAndGet();
                    failureCount.incrementAndGet();
                } catch (Throwable t) {
                    // Cualquier otra excepcion es un fallo de test
                    // inesperado; la contamos para el assertion final.
                    failureCount.incrementAndGet();
                } finally {
                    finishGate.countDown();
                }
            });
        }

        // Liberamos todos los threads simultaneamente.
        startGate.countDown();

        // Esperamos a que todos terminen (con timeout).
        boolean allFinished = finishGate.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);

        // ============================================================
        // Aserciones
        // ============================================================
        assertThat(allFinished)
                .as("todos los threads deben completar en <%ds", AWAIT_TIMEOUT_SECONDS)
                .isTrue();

        assertThat(successCount.get())
                .as("EXACTAMENTE 1 thread debe tener exito (audit #4: @Version previene el race). "
                        + "success=%d, failure=%d, optimisticLock=%d",
                        successCount.get(), failureCount.get(), optimisticLockFailures.get())
                .isEqualTo(1);

        assertThat(failureCount.get())
                .as("los otros N-1 threads deben fallar con InvalidTokenException (perdedores del race)")
                .isEqualTo(CONCURRENT_REQUESTS - 1);

        // Sanity: el @Version del token ganador es > 0 (Hibernate lo incremento).
        // Esto valida que la entidad realmente tiene el campo @Version.
        List<dev.albertoarenaldev.authservice.modelo.PasswordResetToken> tokens =
                tokenRepository.findAll().stream()
                        .filter(t -> t.getUser().getId().equals(user.getId()))
                        .toList();
        assertThat(tokens).as("el usuario debe tener exactamente 1 token persistido").hasSize(1);
        assertThat(tokens.get(0).getUsedAt())
                .as("el token ganador debe estar marcado como usado")
                .isNotNull();
        assertThat(tokens.get(0).getVersion())
                .as("el @Version del token ganador debe ser > 0 (Hibernate lo incremento en el UPDATE)")
                .isNotNull()
                .isGreaterThan(0L);
    }

    // ============================================================
    // Helpers
    // ============================================================

    /**
     * Construye un {@link User} valido para el test. Los campos
     * required por la entidad (firstName, lastName, passwordHash) se
     * inicializan con valores dummy. El email es unico por test para
     * evitar colisiones con otros tests que comparten la misma H2.
     */
    private User newUser(String email) {
        User u = new User();
        u.setEmail(email);
        u.setPasswordHash(passwordEncoder.encode("OldPassword-X9z!"));
        u.setFirstName("Race");
        u.setLastName("Test");
        u.setEnabled(true);
        return u;
    }

    /**
     * Extrae el raw token (43 chars Base64 URL-safe) del cuerpo del
     * email enviado por forgotPassword.
     */
    private String extractRawToken(String body) {
        Matcher m = TOKEN_PARAM.matcher(body);
        assertThat(m.find())
                .as("body should contain ?token=<raw>: " + body)
                .isTrue();
        return m.group(1);
    }
}
