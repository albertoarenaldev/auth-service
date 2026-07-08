package dev.albertoarenaldev.authservice.service;

/**
 * Application event publicado por {@link PasswordResetService#forgotPassword}
 * dentro del metodo {@code @Transactional}. Lo consume un
 * {@link org.springframework.transaction.event.TransactionalEventListener}
 * con {@code phase = AFTER_COMMIT} en el pool {@code emailExecutor}.
 *
 * <p>El email solo se envia despues de que la transaccion de BD commitea,
 * garantizando que no se envia un correo con un token que fue rolled-back
 * (enlace muerto). En escenarios donde el commit falla, el evento nunca
 * se entrega y no hay envio.
 *
 * @param email   direccion del destinatario (ya normalizada)
 * @param subject asunto del correo
 * @param body    cuerpo en texto plano con el enlace de reset
 */
public record PasswordResetRequestedEvent(String email, String subject, String body) {
}
