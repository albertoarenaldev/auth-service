package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload de POST /api/v1/auth/register.
 *
 * <p>Todos los campos son obligatorios y se validan en el controller con
 * {@code @Valid}. Los mensajes de error los genera el
 * {@code GlobalExceptionHandler} con códigos 400.
 */
public record RegisterRequest(

        @NotBlank
        @Email
        @Size(max = 255)
        String email,

        @NotBlank
        @Size(min = 8, max = 100)
        String password,

        @NotBlank
        @Size(max = 100)
        String firstName,

        @NotBlank
        @Size(max = 100)
        String lastName

) {
}
