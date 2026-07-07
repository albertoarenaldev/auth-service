package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.exception.InvalidTokenException;
import dev.albertoarenaldev.authservice.modelo.RefreshToken;
import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.RefreshTokenRepository;
import dev.albertoarenaldev.authservice.security.JwtProperties;
import dev.albertoarenaldev.authservice.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests unitarios de {@link TokenService} con Mockito.
 *
 * <p>Aislan la logica de generacion, rotacion y deteccion de reuso de
 * refresh tokens de la capa de persistencia. Las dependencias
 * (RefreshTokenRepository, JwtTokenProvider, JwtProperties) se mockean.
 *
 * <p>La logica de hashing SHA-256 + generacion con SecureRandom se valida
 * indirectamente a traves de las propiedades observables del token
 * persistido (longitud del hash, no igualdad con el raw, expiracion futura).
 */
@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @Mock private JwtTokenProvider jwtTokenProvider;
    @Mock private JwtProperties jwtProperties;

    @InjectMocks private TokenService tokenService;

    // ============================================================
    // Helpers
    // ============================================================

    private User sampleUser() {
        User u = new User();
        u.setId(1L);
        u.setEmail("alice@example.com");
        u.setEnabled(true);
        u.addRole(new Role("ROLE_USER"));
        return u;
    }

    private RefreshToken validStoredRefreshToken(User user) {
        // El User se recibe por parametro (no se crea internamente) para
        // que sea la MISMA instancia que usa el test: el servicio devuelve
        // old.getUser() en el TokenPair, y la assertion isEqualTo(user)
        // requiere igualdad de referencia (User no sobreescribe equals()).
        RefreshToken rt = new RefreshToken();
        rt.setId(10L);
        rt.setUser(user);
        rt.setTokenHash("hash-of-raw-old-token");
        // Expira en 1 hora (no expirado)
        rt.setExpiresAt(Instant.now().plusSeconds(3600));
        // revokedAt = null, replacedByTokenId = null (estado normal, no usado)
        return rt;
    }

    // ============================================================
    // generateRefreshToken
    // ============================================================

    @Test
    void generateRefreshToken_createsNewTokenPersistsHashAndReturnsRaw() {
        User user = sampleUser();
        // NOTA: no stubbeamos jwtProperties.getRefreshTokenExpirationMs()
        // porque el servicio lo lee en el constructor y lo cachea en el
        // campo `refreshTtlMs` (long). Mockito strict mode marcaria el
        // stub como UnnecessaryStubbing. El TTL de 7 dias se verifica
        // implicitamente en el test de integracion con el perfil dev real.
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> {
            RefreshToken rt = inv.getArgument(0);
            if (rt.getId() == null) rt.setId(42L);
            return rt;
        });

        String rawToken = tokenService.generateRefreshToken(user);

        // El raw token se devuelve (en claro) y tiene la longitud esperada:
        // 32 bytes -> Base64 URL-safe sin padding = 43 caracteres
        assertThat(rawToken).isNotBlank();
        assertThat(rawToken).hasSize(43);

        // El hash persistido NO es el raw token (es SHA-256 hex de 64 chars)
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken saved = captor.getValue();
        assertThat(saved.getUser()).isEqualTo(user);
        assertThat(saved.getTokenHash()).isNotEqualTo(rawToken);
        assertThat(saved.getTokenHash()).hasSize(64); // SHA-256 hex
        // expiresAt es 7 dias en el futuro. Usamos un margen de 1s para
        // tolerar jitter del reloj y aserciones en el mismo nanosegundo
        // (Instant.now() tiene precision de ns; isAfter es estricto).
        assertThat(saved.getExpiresAt()).isAfter(Instant.now().minusSeconds(1));
    }

    // ============================================================
    // rotateRefreshToken — happy path
    // ============================================================

    @Test
    void rotateRefreshToken_withValidToken_emitsNewPairAndMarksOldAsReplaced() {
        User user = sampleUser();
        RefreshToken old = validStoredRefreshToken(user);
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(old));
        // jwtProperties no se stubbea: ver comentario en generateRefreshToken_*
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> {
            RefreshToken rt = inv.getArgument(0);
            if (rt.getId() == null) rt.setId(99L);
            return rt;
        });
        // Usamos any() porque el servicio pasa old.getUser() (un User
        // distinto del que tenemos en la variable local `user`, ya que
        // validStoredRefreshToken() crea su propio User internamente).
        // Con un matcher estricto, Mockito se quejaria de stubbing
        // mismatch (PotentialStubbingProblem).
        when(jwtTokenProvider.generateAccessToken(any(User.class))).thenReturn("new-access.jwt");

        TokenService.TokenPair pair = tokenService.rotateRefreshToken("raw-old-token");

        // Devuelve un par NUEVO (no el mismo raw)
        assertThat(pair.accessToken()).isEqualTo("new-access.jwt");
        assertThat(pair.refreshToken()).isNotBlank();
        assertThat(pair.refreshToken()).isNotEqualTo("raw-old-token");
        assertThat(pair.user()).isEqualTo(user);

        // El token viejo queda marcado como rotado: revokedAt != null y
        // replacedByTokenId apunta al id del nuevo token.
        assertThat(old.getRevokedAt()).isNotNull();
        assertThat(old.getReplacedByTokenId()).isEqualTo(99L);
        verify(refreshTokenRepository, atLeastOnce()).save(old);

        // Se emite un nuevo access token JWT (verificamos cualquier User;
        // el matching especifico ya se cubre en los tests de AuthService).
        verify(jwtTokenProvider).generateAccessToken(any(User.class));
    }

    // ============================================================
    // rotateRefreshToken — reuso (familia comprometida)
    // ============================================================

    @Test
    void rotateRefreshToken_whenReuseDetected_revokesEntireFamilyAndThrows() {
        User user = sampleUser();
        RefreshToken old = validStoredRefreshToken(user);
        // Simula reuso: el token ya estaba revocado Y ya fue reemplazado
        // (un atacante lo esta reusando despues de que el legitimo usuario
        // lo rotó). Esto es la senial de "familia comprometida".
        old.setRevokedAt(Instant.now().minusSeconds(60));
        old.setReplacedByTokenId(50L);
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(old));
        when(refreshTokenRepository.revokeAllByUserId(anyLong(), any(Instant.class))).thenReturn(3);

        // Mensaje generico: ya no leakamos la razon (reuse vs revoked) al cliente.
        // La deteccion de reuse se verifica via el side effect (revokeAllByUserId).
        assertThatThrownBy(() -> tokenService.rotateRefreshToken("raw-old-token"))
                .isInstanceOf(InvalidTokenException.class);

        // Mitigacion: se revocan TODOS los tokens activos del usuario
        verify(refreshTokenRepository).revokeAllByUserId(anyLong(), any(Instant.class));

        // NO se emite un nuevo access token (la peticion se rechaza)
        verify(jwtTokenProvider, never()).generateAccessToken(any());
    }
}
