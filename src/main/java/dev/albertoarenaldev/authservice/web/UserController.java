package dev.albertoarenaldev.authservice.web;

import dev.albertoarenaldev.authservice.dto.ChangePasswordRequest;
import dev.albertoarenaldev.authservice.dto.UpdateProfileRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controlador REST para el perfil del usuario autenticado.
 * Expone los endpoints protegidos bajo {@code /api/v1/users}.
 *
 * <p>Endpoints (Fase 6):
 * <ul>
 *   <li>{@code GET /me} — devuelve el perfil del usuario autenticado.</li>
 *   <li>{@code PUT /me} — actualiza nombre y apellido.</li>
 *   <li>{@code POST /me/password} — cambia la contraseña (requiere
 *       la actual + la nueva, revoca todas las sesiones activas).</li>
 * </ul>
 *
 * <p>Todos los endpoints requieren JWT valido en el header
 * {@code Authorization}. El email del usuario se extrae del
 * {@link Authentication} poblado por
 * {@code JwtAuthenticationFilter} (principal = email).
 * {@code SecurityConfig} protege {@code /api/v1/users/**} con
 * {@code .anyRequest().authenticated()}.
 *
 * <p>Los errores de negocio (400 Bean Validation, 401 password
 * incorrecta, 401 token invalido, 403 sin permisos) se traducen a
 * JSON estandarizado por {@code GlobalExceptionHandler}.
 */
@RestController
@RequestMapping("/api/v1/users")
public class UserController {

    private final AuthService authService;

    public UserController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Devuelve el perfil del usuario autenticado.
     *
     * @param authentication inyectado por Spring Security (contiene
     *                        el email como principal)
     * @return 200 OK con {@link UserResponse}
     */
    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        String email = authentication.getName();
        return ResponseEntity.ok(authService.getCurrentUser(email));
    }

    /**
     * Actualiza nombre y apellido del usuario autenticado.
     *
     * @param authentication email del JWT como principal
     * @param request        payload con firstName y lastName
     * @return 200 OK con el perfil actualizado
     * @throws 400 si el body no pasa Bean Validation
     */
    @PutMapping("/me")
    public ResponseEntity<UserResponse> updateProfile(
            Authentication authentication,
            @Valid @RequestBody UpdateProfileRequest request) {
        String email = authentication.getName();
        return ResponseEntity.ok(authService.updateProfile(email, request));
    }

    /**
     * Cambia la contraseña del usuario autenticado.
     *
     * <p>Verifica la contraseña actual, hashea la nueva con BCrypt(12),
     * y revoca todos los refresh tokens activos (OWASP ASVS V3.5:
     * las sesiones existentes dejan de ser validas tras un cambio de
     * credenciales). Las tres operaciones son atomicas dentro de una
     * misma transaccion.
     *
     * @param authentication email del JWT como principal
     * @param request        payload con currentPassword y newPassword
     * @return 204 No Content
     * @throws 400 si el body no pasa Bean Validation
     * @throws 401 si la contraseña actual es incorrecta
     */
    @PostMapping("/me/password")
    public ResponseEntity<Void> changePassword(
            Authentication authentication,
            @Valid @RequestBody ChangePasswordRequest request) {
        String email = authentication.getName();
        authService.changePassword(email, request);
        return ResponseEntity.noContent().build();
    }
}
