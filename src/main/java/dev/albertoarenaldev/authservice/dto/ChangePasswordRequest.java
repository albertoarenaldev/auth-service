package dev.albertoarenaldev.authservice.dto;

import dev.albertoarenaldev.authservice.validation.StrongPassword;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload de POST /api/v1/users/me/password.
 *
 * <p>El usuario autenticado debe proporcionar su contraseña actual
 * (para verificar que es el legitimo propietario de la cuenta) y la
 * nueva contraseña, que debe cumplir la politica de fortaleza
 * ({@link StrongPassword}, score zxcvbn &gt;= umbral configurado).
 *
 * <p>Tras el cambio, todas las sesiones activas del usuario se revocan
 * (OWASP ASVS V3.5: invalidar sesiones tras cambio de credenciales).
 */
public record ChangePasswordRequest(

        @NotBlank
        String currentPassword,

        @NotBlank
        @Size(min = 8, max = 100)
        @StrongPassword
        String newPassword

) {
}
