package dev.albertoarenaldev.authservice.service.email;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

/**
 * Implementacion no-op del {@link EmailSender}, activa unicamente bajo
 * el perfil {@code test}.
 *
 * <p>En lugar de conectar a un SMTP real (que no existe en CI y
 * aniadiria flakiness), simplemente loguea cada envio a SLF4J. Esto
 * permite a los tests:
 * <ul>
 *   <li>Verificar que {@code send()} fue invocado (capturando logs con
 *       un appender custom o grep por el prefijo {@code [TEST-EMAIL]}).</li>
 *   <li>Confirmar que el body contiene el link esperado sin tener que
 *       parsear MIME.</li>
 * </ul>
 *
 * <p>Spring Boot elige automaticamente entre esta y {@link SmtpEmailSender}
 * segun el perfil sin necesidad de configuracion manual: con
 * {@code spring.profiles.active=test} se inyecta esta; en cualquier otro
 * perfil, la impl SMTP real.
 */
@Service
@Profile("test")
public class NoOpEmailSender implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(NoOpEmailSender.class);

    /**
     * Prefijo reconocible en el log para que tests con Logback's
     * ListAppender (o grep en consola) puedan filtrar las llamadas
     * reales de envio sin tener que mockear el bean.
     */
    private static final String TEST_TAG = "[TEST-EMAIL]";

    @Override
    public void send(String to, String subject, String body) {
        log.info("{} to={} subject='{}' body=\"{}\"",
                TEST_TAG,
                to,
                subject,
                body.replace("\"", "\\\""));
    }
}
