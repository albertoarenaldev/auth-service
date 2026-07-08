package dev.albertoarenaldev.authservice.service.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Implementacion SMTP real del {@link EmailSender}.
 *
 * <p>Solo se activa fuera del perfil {@code test} ({@code @Profile("!test")}).
 * En tests, {@link NoOpEmailSender} toma su lugar automaticamente sin
 * necesidad de {@code @MockBean} ni configurar GreenMail.
 *
 * <p>Usa {@link SimpleMailMessage} (texto plano) en vez de MimeMessage +
 * MimeMessageHelper porque:
 * <ul>
 *   <li>El correo de password reset es one-shot y no requiere HTML ni
 *       adjuntos ni templates.</li>
 *   <li>Texto plano es trivialmente entregable y no dispara filtros
 *       anti-spam por inconsistencias HTML/texto.</li>
 *   <li>Para un proyecto portfolio, la simpleza demuestra criterio
 *       senior mejor que over-engineering con plantillas HTML.</li>
 * </ul>
 *
 * <p><b>Por que el try/catch engulle la excepcion del SMTP:</b> el
 * caller (PasswordResetService) ya ha persistido el token de reset en
 * BD antes de llamar a send(); un fallo del SMTP no debe hacer rollback
 * de la BD. La excepcion se logue a nivel ERROR para el audit log. Se
 * captura especificamente {@link MailException} (unchecked wrapper de
 * Spring sobre la {@code MessagingException} de Jakarta): esto deja
 * propagar bugs reales del caller (NPE, IllegalStateException) en vez
 * de enmascararlos como "fallo de SMTP". Un retry asincrono se podria
 * a\u00f1adir en Fase 7 sin afectar este contrato.
 */
@Service
@Profile("!test")
public class SmtpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(SmtpEmailSender.class);

    private final JavaMailSender javaMailSender;

    public SmtpEmailSender(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    @Override
    public void send(String to, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        try {
            javaMailSender.send(message);
            log.debug("Email sent to {} subject='{}'", to, subject);
        } catch (MailException ex) {
            log.error("Failed to send email to {} subject='{}' (token already persisted; user can retry): {}",
                    to, subject, ex.getMessage(), ex);
        }
    }
}
