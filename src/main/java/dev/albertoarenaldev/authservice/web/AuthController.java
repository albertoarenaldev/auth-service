package dev.albertoarenaldev.authservice.web;

import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ForgotPasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.ResetPasswordRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.service.AuthService;
import dev.albertoarenaldev.authservice.service.PasswordResetService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Controlador REST de autenticacion. Expone los endpoints publicos del
 * auth-service bajo {@code /api/v1/auth}.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>{@code GET /health} - health check publico (smoke tests, CI).</li>
 *   <li>{@code POST /register} - crea un usuario nuevo (requiere verificacion de email).</li>
 *   <li>{@code GET /verify-email} - canjea el token de verificacion y emite tokens.</li>
 *   <li>{@code POST /login} - autentica por email+password y emite tokens.</li>
 *   <li>{@code POST /refresh} - rota el refresh token y emite tokens nuevos.</li>
 *   <li>{@code POST /logout} - revoca un refresh token (logout de un dispositivo).</li>
 *   <li>{@code POST /forgot-password} - inicia el flujo de password reset.</li>
 *   <li>{@code POST /reset-password} - canjea el token y actualiza password.</li>
 * </ul>
 *
 * <p>Todos los endpoints son publicos segun SecurityConfig
 * ({@code /api/v1/auth/**} -> permitAll). La validacion de credenciales,
 * la generacion de tokens y la deteccion de reuso se hacen en
 * {@link AuthService}; el flujo de password reset vive en
 * {@link PasswordResetService}. Este controller solo orquesta el
 * request/response.
 *
 * <p>Los errores de negocio (400 bean validation, 401 credenciales
 * invalidas / token invalido / reset token invalido / reuso de familia,
 * 409 email duplicado) se traducen automaticamente a respuestas JSON
 * estandarizadas por {@code GlobalExceptionHandler} (no se manejan aqui).
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    public AuthController(AuthService authService,
                          PasswordResetService passwordResetService) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
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
     * Registra un usuario nuevo. La cuenta se crea con {@code enabled = false}:
     * el usuario recibe un email de verificacion y debe canjearlo via
     * {@code GET /verify-email?token=...} antes de poder autenticarse.
     *
     * @return 201 Created con {@link UserResponse} (datos del usuario, sin tokens)
     * @throws 400 si el body no pasa la validacion Bean Validation
     * @throws 409 si el email ya esta registrado
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    /**
     * Verifica el email del usuario canjeando el token enviado por correo.
     * Si el token es valido, habilita la cuenta y emite el primer par de
     * tokens (access + refresh).
     *
     * <p>El token se recibe como query param en la URL:
     * {@code /api/v1/auth/verify-email?token=<raw-token>}.
     *
     * @param token token en claro del enlace del correo
     * @return 200 OK con {@link AuthResponse} (access + refresh + user)
     * @throws 401 si el token no existe, expiro, o ya se uso
     */
    @GetMapping("/verify-email")
    public ResponseEntity<AuthResponse> verifyEmail(@RequestParam("token") String token) {
        return ResponseEntity.ok(authService.verifyEmail(token));
    }

    /**
     * Reenvia el email de verificacion para un usuario no verificado.
     *
     * <p>Siempre responde 202 Accepted (exista o no el email, este o no
     * verificado) para mitigar user enumeration. Si el usuario existe y
     * NO esta verificado, el servicio invalida los tokens previos, genera
     * uno nuevo y lo envia de forma asincrona.
     *
     * @return 202 Accepted (cuerpo vacio)
     * @throws 400 si el body no pasa Bean Validation
     */
    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resendVerification(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.resendVerification(request.email());
        return ResponseEntity.accepted().build();
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

    /**
     * Inicia el flujo de password reset. Devuelve SIEMPRE 202 Accepted
     * (exista o no el email en BD) para mitigar user enumeration
     * (OWASP Authentication Cheat Sheet). Si el email existe, el servicio
     * {@link PasswordResetService} genera un token opaco, lo persiste
     * hasheado (SHA-256) y envia el correo de forma sincrona dentro del
     * handler (latencia SMTP ~150-250ms en el caso feliz).
     *
     * <p>El correo nunca se envia a emails no registrados; en ese caso
     * el servicio registra un evento de auditoria anonimo (prefijo MD5
     * del email, sin cleartext) y devuelve sin enviar correo. La
     * diferencia no es visible al cliente.
     *
     * @return 202 Accepted (cuerpo vacio)
     * @throws 400 si el body no pasa la validacion Bean Validation
     *         (campo email no vacio y formato valido)
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        passwordResetService.forgotPassword(request.email());
        return ResponseEntity.accepted().build();
    }

    /**
     * Canjea un token de password reset y actualiza la contrasena del
     * usuario. La marcacion del token como usado y la actualizacion del
     * passwordHash se hacen atomicamente en una sola transaccion dentro
     * de {@link PasswordResetService}.
     *
     * <p>Si el token es invalido, expiro, ya se uso, o el usuario
     * asociado esta deshabilitado, el servicio lanza
     * {@code InvalidTokenException} (mapeada a HTTP 401 por
     * {@code GlobalExceptionHandler}) con un mensaje generico para no
     * permitir ataques de tipo "oracle" (el atacante no debe poder
     * distinguir las distintas razones del fallo).
     *
     * <p><b>Limitacion conocida (Fase 5):</b> tras este cambio, las
     * sesiones existentes del usuario NO se invalidan automaticamente —
     * quedan como sesiones validas hasta que el access token JWT expire
     * (15 min). Una revocacion explicita de los refresh tokens del
     * usuario seria una defensa en profundidad contra takeover y queda
     * anotada como follow-up.
     *
     * @return 204 No Content (cuerpo vacio)
     * @throws 400 si el body no pasa la validacion Bean Validation
     *         (campo token no vacio, newPassword entre 8-100 chars)
     * @throws 401 si el token no existe, expiro, ya se uso, o el
     *         usuario asociado esta deshabilitado
     */
    @PostMapping("/reset-password")
    public ResponseEntity<Void> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordResetService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.noContent().build();
    }
}
