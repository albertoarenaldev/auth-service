package dev.albertoarenaldev.authservice.web;

import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controlador REST de autenticacion. Expone los endpoints publicos del
 * auth-service bajo {@code /api/v1/auth}.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET /health} - health check publico (smoke tests, CI).</li>
 *   <li>{@code POST /register} - crea un usuario nuevo y emite tokens.</li>
 *   <li>{@code POST /login} - autentica por email+password y emite tokens.</li>
 *   <li>{@code POST /refresh} - rota el refresh token y emite tokens nuevos.</li>
 *   <li>{@code POST /logout} - revoca un refresh token (logout de un dispositivo).</li>
 * </ul>
 *
 * <p>Todos los endpoints (salvo /health) son publicos segun SecurityConfig
 * ({@code /api/v1/auth/**} -> permitAll). La validacion de credenciales,
 * la generacion de tokens y la deteccion de reuso se hacen en
 * {@link AuthService}; este controller solo orquesta el request/response.
 *
 * <p>Los errores de negocio (409 email duplicado, 401 credenciales invalidas,
 * 401 token invalido) se traducen automaticamente a respuestas JSON
 * estandarizadas por {@code GlobalExceptionHandler} (no se manejan aqui).
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Health check publico. Devuelve 200 si la app esta levantada.
     * Usado por load balancers, smoke tests de CI, y el
     * {@code SecurityConfigTest} para verificar que Spring Security
     * deja pasar {@code /api/v1/auth/**}.
     */
    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }

    /**
     * Registra un usuario nuevo y emite el primer par de tokens.
     *
     * @return 201 Created con {@link AuthResponse} (access + refresh + user)
     * @throws 400 si el body no pasa la validacion Bean Validation
     * @throws 409 si el email ya esta registrado
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Autentica por email+password y emite un nuevo par de tokens.
     *
     * @return 200 OK con {@link AuthResponse}
     * @throws 400 si el body no pasa la validacion
     * @throws 401 si las credenciales son invalidas (mensaje generico para
     *         no permitir user enumeration)
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * Rota el refresh token presentado y emite tokens nuevos.
     * La deteccion de reuso y la revocacion de familia se hacen en
     * {@link AuthService} (ver {@code TokenService.rotateRefreshToken}).
     *
     * @return 200 OK con {@link AuthResponse} (nuevo access + nuevo refresh)
     * @throws 400 si el body no pasa la validacion
     * @throws 401 si el token no existe, expiro, o se detecta reuso
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    /**
     * Cierra una sesion revocando el refresh token presentado.
     * Es idempotente: si el token no existe o ya estaba revocado,
     * no lanza excepcion.
     *
     * @return 204 No Content
     * @throws 400 si el body no pasa la validacion
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshRequest request) {
        authService.logout(request.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
