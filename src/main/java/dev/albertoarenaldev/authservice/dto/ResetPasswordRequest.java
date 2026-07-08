package dev.albertoarenaldev.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Payload de POST /api/v1/auth/reset-password.
 *
 * <p>El cliente llega aqui desde el enlace enviado por correo. El token
 * es el que recibio en el mail (NO el hash: el hash vive en BD, el token
 * raw solo lo ve el usuario una vez). La nueva password reemplaza a la
 * anterior y todas las sesiones activas del usuario se revocan.
 *
 * <p>Politica de password igual a la de registro: 8-100 chars. Spring
 * Validation aplica las constraints antes de llegar al service.
 */
public record ResetPasswordRequest(

        @NotBlank
        String token,

        @NotBlank
        @Size(min = 8, max = 100)
        String newPassword

) {
}
