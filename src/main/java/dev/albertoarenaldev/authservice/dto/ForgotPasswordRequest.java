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
 * <p>El envio del correo (cuando corresponde) se hace de forma sincrona
 * dentro del handler del request (Fase 5 no introduce {@code @Async}
 * deliberadamente); la latencia del response en el caso feliz es de
 * unos ~150-250ms por el coste del SMTP send. Cuando llegue el rate
 * limiting de Fase 7, podría migrarse a async sin tocar el DTO.
 */
public record ForgotPasswordRequest(

        @NotBlank
        @Email
        String email

) {
}
