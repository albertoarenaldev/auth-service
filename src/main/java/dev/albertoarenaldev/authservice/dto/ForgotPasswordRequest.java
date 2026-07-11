package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Payload de POST /api/v1/auth/forgot-password.
 *
 * <p>El backend siempre responde 202 Accepted, exista o no el email en la
 * base de datos. Esto es deliberado para no permitir user enumeration
 * (un atacante no puede distinguir "email registrado" vs "email libre"
 * midiendo respuestas o mensajes).
 *
 * <p>El envio del correo (cuando corresponde) se hace de forma <b>asincrona</b>
 * tras el commit de la transaccion, via {@code @Async("emailExecutor")} +
 * {@code @TransactionalEventListener(phase = AFTER_COMMIT)}. Esto protege
 * contra DoS (el thread HTTP no espera al SMTP) y contra timing-based user
 * enumeration.
 */
public record ForgotPasswordRequest(

        @NotBlank
        @Email
        String email

) {
}
