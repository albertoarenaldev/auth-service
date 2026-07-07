package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.exception.EmailAlreadyExistsException;
import dev.albertoarenaldev.authservice.exception.InvalidCredentialsException;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.service.TokenService.TokenPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests unitarios de {@link AuthService} con Mockito.
 *
 * <p>Aislan la logica de orquestacion (validaciones, mapeo DTO/Entity,
 * manejo de excepciones) de la capa de persistencia y de seguridad.
 * Las dependencias (UserRepository, RoleRepository, TokenService,
 * PasswordEncoder) se mockean para que el test sea rapido y determinista.
 *
 * <p>Cubre los 3 metodos publicos principales: register, login, refresh.
 * Logout se delega trivialmente a TokenService (ya cubierto por
 * {@code TokenServiceTest} o por los tests de integracion de AuthController).
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private TokenService tokenService;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks private AuthService authService;

    // ============================================================
    // Helpers
    // ============================================================

    private Role userRole() {
        return new Role("ROLE_USER");
    }

    private User sampleUser() {
        User u = new User();
        u.setId(1L);
        u.setEmail("alice@example.com");
        u.setPasswordHash("hashed-password");
        u.setFirstName("Alice");
        u.setLastName("Doe");
        u.setEnabled(true);
        u.addRole(userRole());
        return u;
    }

    private RegisterRequest sampleRegisterRequest() {
        return new RegisterRequest("alice@example.com", "Password123!", "Alice", "Doe");
    }

    // ============================================================
    // register
    // ============================================================

    @Test
    void register_withNewEmail_createsUserAndReturnsTokens() {
        RegisterRequest req = sampleRegisterRequest();
        when(userRepository.existsByEmail(req.email())).thenReturn(false);
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole()));
        when(passwordEncoder.encode(req.password())).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(1L);
            return u;
        });
        when(tokenService.generateAccessToken(any(User.class))).thenReturn("access.jwt.token");
        when(tokenService.generateRefreshToken(any(User.class))).thenReturn("raw-refresh-token");

        AuthResponse response = authService.register(req);

        // La respuesta incluye los tokens emitidos y los datos del usuario
        assertThat(response.accessToken()).isEqualTo("access.jwt.token");
        assertThat(response.refreshToken()).isEqualTo("raw-refresh-token");
        assertThat(response.user().email()).isEqualTo("alice@example.com");
        assertThat(response.user().firstName()).isEqualTo("Alice");
        assertThat(response.user().lastName()).isEqualTo("Doe");
        assertThat(response.user().roles()).containsExactly("ROLE_USER");

        // Verifica que el password fue hasheado (no se guardo en claro) y
        // que el usuario quedo habilitado con el rol por defecto.
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User saved = userCaptor.getValue();
        assertThat(saved.getPasswordHash()).isEqualTo("hashed-password");
        assertThat(saved.getPasswordHash()).isNotEqualTo(req.password());
        assertThat(saved.getEnabled()).isTrue();
        assertThat(saved.getRoles()).extracting(Role::getName).containsExactly("ROLE_USER");
    }

    @Test
    void register_withDuplicateEmail_throwsEmailAlreadyExistsException() {
        RegisterRequest req = sampleRegisterRequest();
        when(userRepository.existsByEmail(req.email())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(EmailAlreadyExistsException.class);

        // No debe intentar guardar ni emitir tokens si el email ya existe
        verify(userRepository, never()).save(any(User.class));
        verify(tokenService, never()).generateAccessToken(any());
        verify(tokenService, never()).generateRefreshToken(any());
    }

    // ============================================================
    // login
    // ============================================================

    @Test
    void login_withValidCredentials_returnsTokensAndUpdatesLastLogin() {
        User user = sampleUser();
        LoginRequest req = new LoginRequest("alice@example.com", "Password123!");
        when(userRepository.findByEmail(req.email())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(req.password(), user.getPasswordHash())).thenReturn(true);
        when(tokenService.generateAccessToken(user)).thenReturn("access.jwt.token");
        when(tokenService.generateRefreshToken(user)).thenReturn("raw-refresh-token");

        AuthResponse response = authService.login(req);

        assertThat(response.accessToken()).isEqualTo("access.jwt.token");
        assertThat(response.refreshToken()).isEqualTo("raw-refresh-token");
        assertThat(response.user().email()).isEqualTo("alice@example.com");

        // lastLoginAt se actualiza como efecto colateral del login exitoso
        assertThat(user.getLastLoginAt()).isNotNull();
        verify(userRepository).save(user);
    }

    @Test
    void login_withInvalidPassword_throwsInvalidCredentialsException() {
        User user = sampleUser();
        LoginRequest req = new LoginRequest("alice@example.com", "WrongPassword!");
        when(userRepository.findByEmail(req.email())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(req.password(), user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(InvalidCredentialsException.class);

        // Password incorrecto: no emitir tokens ni persistir lastLoginAt
        verify(userRepository, never()).save(any(User.class));
        verify(tokenService, never()).generateAccessToken(any());
        verify(tokenService, never()).generateRefreshToken(any());
    }

    // ============================================================
    // refresh
    // ============================================================

    @Test
    void refresh_withValidToken_returnsNewTokensFromTokenService() {
        User user = sampleUser();
        TokenPair pair = new TokenPair("new-access.jwt", "new-raw-refresh", user);
        RefreshRequest req = new RefreshRequest("old-raw-refresh-token");
        when(tokenService.rotateRefreshToken(req.refreshToken())).thenReturn(pair);

        AuthResponse response = authService.refresh(req);

        // La respuesta envuelve el TokenPair devuelto por TokenService
        assertThat(response.accessToken()).isEqualTo("new-access.jwt");
        assertThat(response.refreshToken()).isEqualTo("new-raw-refresh");
        assertThat(response.user().email()).isEqualTo("alice@example.com");
        // refresh es un thin wrapper: no debe tocar la DB ni passwordEncoder
        verify(userRepository, never()).findByEmail(any());
        verify(passwordEncoder, never()).matches(any(), any());
    }
}
