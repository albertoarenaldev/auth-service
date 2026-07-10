package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload de PUT /api/v1/users/me.
 *
 * <p>Permite actualizar nombre y apellido del usuario autenticado.
 * El email no se actualiza por este endpoint (requiere un flujo
 * separado con verificacion de email para evitar account takeover).
 */
public record UpdateProfileRequest(

        @NotBlank
        @Size(max = 100)
        String firstName,

        @NotBlank
        @Size(max = 100)
        String lastName

) {
}
