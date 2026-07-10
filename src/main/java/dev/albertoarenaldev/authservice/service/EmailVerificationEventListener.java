package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.service.email.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Listener asincrono de {@link EmailVerificationRequestedEvent}.
 *
 * <p>Mismo patron que {@link PasswordResetEventListener}:
 * <ul>
 *   <li>{@link TransactionalEventListener} con AFTER_COMMIT: el email
 *       solo se envia si la transaccion de BD commitea.</li>
 *   <li>{@link Async} con {@code emailExecutor}: el envio corre en un
 *       thread del pool dedicado, sin bloquear el request HTTP.</li>
 * </ul>
 *
 * <p>Si el envio falla, se loguea a ERROR y el token persistido sigue
 * siendo valido; el usuario puede solicitar reenvio.
 */
@Component
public class EmailVerificationEventListener {

    private static final Logger log = LoggerFactory.getLogger(EmailVerificationEventListener.class);

    private final EmailSender emailSender;

    public EmailVerificationEventListener(EmailSender emailSender) {
        this.emailSender = emailSender;
    }

    @Async("emailExecutor")
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onEmailVerificationRequested(EmailVerificationRequestedEvent event) {
        try {
            emailSender.send(event.email(), event.subject(), event.body());
        } catch (Exception ex) {
            log.error("Async verification email send failed for {} subject='{}' (token persisted; user can retry): {}",
                    event.email(), event.subject(), ex.getMessage(), ex);
        }
    }
}
