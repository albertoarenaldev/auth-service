package dev.albertoarenaldev.authservice.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Config para password reset — bindea el prefijo {@code app.password-reset.*}
 * desde {@code application.properties}.
 *
 * <p>Campos:
 * <ul>
 *   <li>{@code baseUrl} — URL del frontend donde el usuario canjea el
 *       token (ej. {@code https://app.example.com/reset-password}). El
 *       correo contiene un enlace del estilo
 *       {@code {baseUrl}?token=<opaque-token>}. El frontend lee el query
 *       param, llama a {@code POST /api/v1/auth/reset-password}, recibe
 *       204 y devuelve al usuario al login.</li>
 *   <li>{@code appName} — nombre de la aplicación que aparece en el
 *       subject y cuerpo del correo (ej. "Auth Service"). Default si
 *       falta la propiedad.</li>
 * </ul>
 *
 * <p>Se valida con {@link Validated} al construir el bean: si falta una
 * propiedad requerida (baseUrl), la app falla al arrancar con mensaje
 * claro (no en runtime con NullPointerException en mitad del request).
 *
 * <p>El TTL del token ({@code app.jwt.password-reset-token-expiration-ms},
 * 15 min por defecto) se hereda de {@code JwtProperties} existente —
 * el nombre del prefijo está heredado de commits previos y se mantiene
 * deliberadamente para evitar una migración de propiedades que obligaría
 * a tocar la base instalada.
 */
@ConfigurationProperties(prefix = "app.password-reset")
@Validated
public class PasswordResetProperties {

    @NotBlank
    private String baseUrl;

    private String appName = "Auth Service";

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }
}
