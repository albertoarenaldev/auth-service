package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Payload de POST /api/v1/auth/refresh.
 *
 * <p>El cliente envía el refresh token recibido en el login (o en un refresh
 * anterior) para obtener un nuevo access token + nuevo refresh token
 * (rotación con detección de reuso).
 */
public record RefreshRequest(

        @NotBlank
        String refreshToken

) {
}
