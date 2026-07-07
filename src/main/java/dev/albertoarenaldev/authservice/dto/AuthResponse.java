package dev.albertoarenaldev.authservice.dto;

/**
 * Response de register / login / refresh.
 *
 * <p>Incluye:
 * <ul>
 *   <li>{@code accessToken} — JWT firmado (15 min default), stateless</li>
 *   <li>{@code refreshToken} — token opaco (7 días default), vive en DB,
 *       se rota en cada refresh</li>
 *   <li>{@code user} — info pública del usuario (sin password hash)</li>
 * </ul>
 */
public record AuthResponse(

        String accessToken,
        String refreshToken,
        UserResponse user

) {
}
