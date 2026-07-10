package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.config.PasswordResetProperties;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.ChangePasswordRequest;
import dev.albertoarenaldev.authservice.dto.LoginRequest;
import dev.albertoarenaldev.authservice.dto.RefreshRequest;
import dev.albertoarenaldev.authservice.dto.RegisterRequest;
import dev.albertoarenaldev.authservice.dto.UpdateProfileRequest;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.exception.EmailAlreadyExistsException;
import dev.albertoarenaldev.authservice.exception.InvalidCredentialsException;
import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.EmailVerificationToken;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.EmailVerificationTokenRepository;
import dev.albertoarenaldev.authservice.repository.RoleRepository;
import dev.albertoarenaldev.authservice.repository.UserRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import dev.albertoarenaldev.authservice.service.TokenService.TokenPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import io.micrometer.core.instrument.Counter;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests unitarios de {@link AuthService} con Mockito.
 *
 * <p>Aislan la logica de orquestacion (validaciones, mapeo DTO/Entity,
 * manejo de excepciones) de la capa de persistencia y de seguridad.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private TokenService tokenService;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private EmailVerificationTokenRepository verificationTokenRepository;
    @Mock private PasswordResetProperties resetProperties;
    @Mock private JwtProperties jwtProperties;
    @Mock private ApplicationEventPublisher eventPublisher;
    @Mock private AuditService auditService;

    @Mock(name = "loginSuccessCounter") private Counter loginSuccessCounter;
    @Mock(name = "loginFailureCounter") private Counter loginFailureCounter;
    @Mock(name = "registerCounter") private Counter registerCounter;
    @Mock(name = "emailVerifiedCounter") private Counter emailVerifiedCounter;

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

    private User unverifiedUser() {
        User u = sampleUser();
        u.setEnabled(false);
        return u;
    }

    private RegisterRequest sampleRegisterRequest() {
        return new RegisterRequest("alice@example.com", "Password123!", "Alice", "Doe");
    }

    private void stubVerificationTokenDependencies() {
        when(resetProperties.getVerificationBaseUrl()).thenReturn("http://localhost:5173/verify-email");
        when(resetProperties.getAppName()).thenReturn("Auth Service");
    }

    // ============================================================
    // register
    // ============================================================

    @Test
    void register_withNewEmail_createsUnverifiedUserAndSendsEmail() {
        RegisterRequest req = sampleRegisterRequest();
        stubVerificationTokenDependencies();
        when(userRepository.existsByEmail(req.email())).thenReturn(false);
        when(roleRepository.findByName("ROLE_USER")).thenReturn(Optional.of(userRole()));
        when(passwordEncoder.encode(req.password())).thenReturn("hashed-password");
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(1L);
            return u;
        });

        UserResponse response = authService.register(req);

        // Solo datos del usuario, sin tokens
        assertThat(response.email()).isEqualTo("alice@example.com");
        assertThat(response.firstName()).isEqualTo("Alice");
        assertThat(response.lastName()).isEqualTo("Doe");
        assertThat(response.roles()).containsExactly("ROLE_USER");

        // El usuario se guarda con enabled=false (default)
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User saved = userCaptor.getValue();
        assertThat(saved.getPasswordHash()).isEqualTo("hashed-password");
        assertThat(saved.isEnabled()).isFalse();

        // Se persiste un token de verificacion
        verify(verificationTokenRepository).save(any(EmailVerificationToken.class));
        // Se publica evento para envio de email
        verify(eventPublisher).publishEvent(any(EmailVerificationRequestedEvent.class));
    }

    @Test
    void register_withDuplicateEmail_throwsEmailAlreadyExistsException() {
        RegisterRequest req = sampleRegisterRequest();
        when(userRepository.existsByEmail(req.email())).thenReturn(true);

        assertThatThrownBy(() -> authService.register(req))
                .isInstanceOf(EmailAlreadyExistsException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(verificationTokenRepository, never()).save(any());
        verify(eventPublisher, never()).publishEvent(any());
    }

    // ============================================================
    // verifyEmail
    // ============================================================

    @Test
    void verifyEmail_withValidToken_enablesUserAndReturnsTokens() {
        User user = unverifiedUser();
        String rawToken = SecureTokenHasher.generateRawToken();
        String tokenHash = SecureTokenHasher.hashToken(rawToken);

        EmailVerificationToken token = new EmailVerificationToken();
        token.setId(10L);
        token.setUser(user);
        token.setTokenHash(tokenHash);
        token.setExpiresAt(Instant.now().plusSeconds(3600));

        when(verificationTokenRepository.findByTokenHash(tokenHash)).thenReturn(Optional.of(token));
        when(tokenService.generateAccessToken(user)).thenReturn("access.jwt.token");
        when(tokenService.generateRefreshToken(user)).thenReturn("raw-refresh-token");

        AuthResponse response = authService.verifyEmail(rawToken);

        assertThat(response.accessToken()).isEqualTo("access.jwt.token");
        assertThat(response.refreshToken()).isEqualTo("raw-refresh-token");
        assertThat(response.user().email()).isEqualTo("alice@example.com");

        // El usuario queda habilitado
        assertThat(user.isEnabled()).isTrue();
        verify(userRepository).save(user);
        // El token se marca como usado
        assertThat(token.getUsedAt()).isNotNull();
        verify(verificationTokenRepository).save(token);
    }

    @Test
    void verifyEmail_withUnknownToken_throwsInvalidTokenException() {
        when(verificationTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.verifyEmail("bogus-token"))
                .isInstanceOf(InvalidTokenException.class);

        verify(userRepository, never()).save(any(User.class));
        verify(tokenService, never()).generateAccessToken(any());
        verify(tokenService, never()).generateRefreshToken(any());
    }

    @Test
    void verifyEmail_withAlreadyUsedToken_throwsInvalidTokenException() {
        User user = unverifiedUser();
        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setUsedAt(Instant.now());
        token.setExpiresAt(Instant.now().plusSeconds(3600));

        when(verificationTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> authService.verifyEmail("used-token"))
                .isInstanceOf(InvalidTokenException.class);

        assertThat(user.isEnabled()).isFalse();
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void verifyEmail_withExpiredToken_throwsInvalidTokenException() {
        User user = unverifiedUser();
        EmailVerificationToken token = new EmailVerificationToken();
        token.setUser(user);
        token.setExpiresAt(Instant.now().minusSeconds(1));

        when(verificationTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(token));

        assertThatThrownBy(() -> authService.verifyEmail("expired-token"))
                .isInstanceOf(InvalidTokenException.class);

        assertThat(user.isEnabled()).isFalse();
    }

    // ============================================================
    // resendVerification
    // ============================================================

    @Test
    void resendVerification_withUnverifiedUser_generatesNewTokenAndSendsEmail() {
        User user = unverifiedUser();
        stubVerificationTokenDependencies();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(verificationTokenRepository.invalidateActiveTokensForUser(anyLong(), any(Instant.class))).thenReturn(1);

        authService.resendVerification("alice@example.com");

        // Invalida tokens previos, genera uno nuevo, envia email
        verify(verificationTokenRepository).invalidateActiveTokensForUser(eq(1L), any(Instant.class));
        verify(verificationTokenRepository).save(any(EmailVerificationToken.class));
        verify(eventPublisher).publishEvent(any(EmailVerificationRequestedEvent.class));
    }

    @Test
    void resendVerification_withAlreadyVerifiedUser_doesNothing() {
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.encode(any(CharSequence.class))).thenReturn("dummy-hash");

        authService.resendVerification("alice@example.com");

        // No genera token ni envia email (anti-enumeration: timing equalization con bcrypt)
        verify(passwordEncoder).encode(any(CharSequence.class));
        verify(verificationTokenRepository, never()).save(any(EmailVerificationToken.class));
        verify(eventPublisher, never()).publishEvent(any(EmailVerificationRequestedEvent.class));
    }

    @Test
    void resendVerification_withNonExistentEmail_doesNothing() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode(any(CharSequence.class))).thenReturn("dummy-hash");

        authService.resendVerification("ghost@example.com");

        verify(passwordEncoder).encode(any(CharSequence.class));
        verify(verificationTokenRepository, never()).save(any(EmailVerificationToken.class));
        verify(eventPublisher, never()).publishEvent(any(EmailVerificationRequestedEvent.class));
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

        verify(userRepository, never()).save(any(User.class));
        verify(tokenService, never()).generateAccessToken(any());
        verify(tokenService, never()).generateRefreshToken(any());
    }

    @Test
    void login_withDisabledAccount_throwsInvalidCredentialsException() {
        User user = unverifiedUser();
        LoginRequest req = new LoginRequest("alice@example.com", "Password123!");
        when(userRepository.findByEmail(req.email())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(req.password(), user.getPasswordHash())).thenReturn(true);

        assertThatThrownBy(() -> authService.login(req))
                .isInstanceOf(InvalidCredentialsException.class);

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

        assertThat(response.accessToken()).isEqualTo("new-access.jwt");
        assertThat(response.refreshToken()).isEqualTo("new-raw-refresh");
        assertThat(response.user().email()).isEqualTo("alice@example.com");
    }

    // ============================================================
    // Perfil del usuario autenticado (Fase 6)
    // ============================================================

    @Test
    void getCurrentUser_withExistingEmail_returnsUserResponse() {
        User user = sampleUser();
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));

        UserResponse response = authService.getCurrentUser("alice@example.com");

        assertThat(response.email()).isEqualTo("alice@example.com");
        assertThat(response.firstName()).isEqualTo("Alice");
        assertThat(response.lastName()).isEqualTo("Doe");
        assertThat(response.roles()).containsExactly("ROLE_USER");
    }

    @Test
    void getCurrentUser_withNonExistentEmail_throwsInvalidCredentialsException() {
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.getCurrentUser("ghost@example.com"))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid credentials");
    }

    @Test
    void updateProfile_withValidData_updatesNameAndReturnsUserResponse() {
        User user = sampleUser();
        UpdateProfileRequest req = new UpdateProfileRequest("Bob", "Smith");
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(User.class))).thenReturn(user);

        UserResponse response = authService.updateProfile("alice@example.com", req);

        assertThat(response.firstName()).isEqualTo("Bob");
        assertThat(response.lastName()).isEqualTo("Smith");
        assertThat(user.getFirstName()).isEqualTo("Bob");
        assertThat(user.getLastName()).isEqualTo("Smith");
        verify(userRepository).save(user);
    }

    @Test
    void updateProfile_withNonExistentEmail_throwsInvalidCredentialsException() {
        UpdateProfileRequest req = new UpdateProfileRequest("Bob", "Smith");
        when(userRepository.findByEmail("ghost@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.updateProfile("ghost@example.com", req))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void changePassword_withCorrectCurrentPassword_updatesHashAndRevokesSessions() {
        User user = sampleUser();
        ChangePasswordRequest req = new ChangePasswordRequest("old-pass", "new-strong-pass");
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("old-pass", user.getPasswordHash())).thenReturn(true);
        when(passwordEncoder.encode("new-strong-pass")).thenReturn("new-hash");
        when(tokenService.revokeAllForUser(1L)).thenReturn(3);

        authService.changePassword("alice@example.com", req);

        assertThat(user.getPasswordHash()).isEqualTo("new-hash");
        verify(userRepository).save(user);
        verify(tokenService).revokeAllForUser(1L);
    }

    @Test
    void changePassword_withWrongCurrentPassword_throwsInvalidCredentialsException() {
        User user = sampleUser();
        ChangePasswordRequest req = new ChangePasswordRequest("wrong-pass", "new-strong-pass");
        when(userRepository.findByEmail("alice@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-pass", user.getPasswordHash())).thenReturn(false);

        assertThatThrownBy(() -> authService.changePassword("alice@example.com", req))
                .isInstanceOf(InvalidCredentialsException.class);

        assertThat(user.getPasswordHash()).isEqualTo("hashed-password");
        verify(userRepository, never()).save(any(User.class));
        verify(tokenService, never()).revokeAllForUser(anyLong());
    }
}
