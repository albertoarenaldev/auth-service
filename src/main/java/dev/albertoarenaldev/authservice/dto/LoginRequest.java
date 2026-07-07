package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Payload de POST /api/v1/auth/login.
 *
 * <p>El backend responde igual (401 InvalidCredentials) si el email no existe
 * o si la contraseña es incorrecta, para no filtrar qué usuarios están
 * registrados.
 */
public record LoginRequest(

        @NotBlank
        @Email
        String email,

        @NotBlank
        String password

) {
}
