package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.service.email.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Listener asincrono de {@link PasswordResetRequestedEvent}.
 *
 * <p>Anotado con dos cosas:
 * <ul>
 *   <li>{@link TransactionalEventListener} con
 *       {@link TransactionPhase#AFTER_COMMIT} — el email solo se envia
 *       si la transaccion de BD (que persistio el token de reset) ha
 *       hecho commit. Si hay rollback, el evento se descarta y no se
 *       envia correo.</li>
 *   <li>{@link Async} con nombre {@code emailExecutor} — el envio
 *       corre en un thread del pool dedicado (ver
 *       {@link dev.albertoarenaldev.authservice.config.AsyncConfig}),
 *       liberando el thread HTTP del request original.</li>
 * </ul>
 *
 * <p><b>Defensa en profundidad:</b> el listener captura cualquier
 * excepcion del envio y la logue a nivel ERROR. Nunca propaga al
 * caller (no hay caller en este punto, el HTTP ya respondio 202). El
 * token persistido en BD sigue siendo valido; el usuario puede repetir
 * el request para reintentar.
 */
@Component
public class PasswordResetEventListener {

    private static final Logger log = LoggerFactory.getLogger(PasswordResetEventListener.class);

    private final EmailSender emailSender;

    public PasswordResetEventListener(EmailSender emailSender) {
        this.emailSender = emailSender;
    }

    @Async("emailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onPasswordResetRequested(PasswordResetRequestedEvent event) {
        try {
            emailSender.send(event.email(), event.subject(), event.body());
        } catch (Exception ex) {
            log.error("Async email send failed for {} subject='{}' (token persisted; user can retry): {}",
                    event.email(), event.subject(), ex.getMessage(), ex);
        }
    }
}
