package dev.albertoarenaldev.authservice.service;

/**
 * Application event publicado por {@link AuthService#register}
 * dentro del metodo {@code @Transactional}. Lo consume
 * {@link EmailVerificationEventListener} con {@code phase = AFTER_COMMIT}
 * en el pool {@code emailExecutor}.
 *
 * <p>El email solo se envia despues de que la transaccion de BD commitea,
 * garantizando que no se envia un correo con un token que fue rolled-back.
 *
 * @param email   direccion del destinatario (ya normalizada)
 * @param subject asunto del correo
 * @param body    cuerpo en texto plano con el enlace de verificacion
 */
public record EmailVerificationRequestedEvent(String email, String subject, String body) {
}
