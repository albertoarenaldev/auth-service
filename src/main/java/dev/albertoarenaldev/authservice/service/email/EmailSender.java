package dev.albertoarenaldev.authservice.service.email;

/**
 * Abstraccion para el envio de correos transaccionales del auth-service.
 *
 * <p>Tener una interfaz (en vez de inyectar directamente
 * {@code JavaMailSender}) permite:
 * <ul>
 *   <li>Sustituir la impl SMTP real por un stub en los tests sin tocar
 *       Spring config ni a\u00f1adir {@code @MockBean} en cada test.</li>
 *   <li>Futuras migraciones a otros proveedores (SES, SendGrid, Mailgun)
 *       sin tocar el codigo de los servicios que envian correo.</li>
 * </ul>
 *
 * <p>Las dos implementaciones viven en el mismo paquete y Spring Boot
 * elige la correcta segun el perfil activo:
 * {@link SmtpEmailSender} (todos los perfiles salvo test, conecta al SMTP
 * real) y {@link NoOpEmailSender} (perfil test, loguea el envio a
 * SLF4J para verificar en tests sin tocar SMTP).
 */
public interface EmailSender {

    /**
     * Envia un correo electronico de texto plano.
     *
     * @param to      direccion del destinatario (ya validada por el caller)
     * @param subject asunto del correo
     * @param body    cuerpo en texto plano
     */
    void send(String to, String subject, String body);
}
