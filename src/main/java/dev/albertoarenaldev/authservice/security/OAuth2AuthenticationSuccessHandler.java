package dev.albertoarenaldev.authservice.security;

import dev.albertoarenaldev.authservice.config.OAuth2Properties;
import dev.albertoarenaldev.authservice.dto.AuthResponse;
import dev.albertoarenaldev.authservice.dto.UserResponse;
import dev.albertoarenaldev.authservice.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * Handler que se ejecuta tras un login OAuth2 exitoso (Google, GitHub, etc.).
 *
 * <p>Flujo:
 * <ol>
 *   <li>Extrae el email y nombre del {@link OAuth2User} autenticado.</li>
 *   <li>Busca o crea un usuario local via
 *       {@link AuthService#findOrCreateOAuth2User(String, String, String)}.</li>
 *   <li>Genera el par de tokens JWT (access + refresh).</li>
 *   <li>Redirige al frontend con los tokens como query params:
 *       {@code {redirectUri}?accessToken=...&refreshToken=...}</li>
 * </ol>
 *
 * <p>No usa sesiones HTTP: los tokens viajan en la URL de redireccion
 * y el frontend los almacena (memoria + httpOnly cookie para el refresh).
 * Tras la redireccion, el frontend llama a los endpoints protegidos
 * normalmente con {@code Authorization: Bearer}.
 */
@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2AuthenticationSuccessHandler.class);

    private final AuthService authService;
    private final OAuth2Properties oauth2Properties;

    public OAuth2AuthenticationSuccessHandler(AuthService authService,
                                               OAuth2Properties oauth2Properties) {
        this.authService = authService;
        this.oauth2Properties = oauth2Properties;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        // GitHub no devuelve email si el usuario no tiene email publico.
        // En ese caso, informamos al cliente en vez de NPE.
        if (email == null || email.isBlank()) {
            log.warn("OAuth2 login failed: provider did not return an email");
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Email not available from OAuth2 provider. Set a public email in GitHub or use Google login.");
            return;
        }

        String name = oauth2User.getAttribute("name");
        if (name == null) {
            name = email.split("@")[0];
        }

        log.info("OAuth2 login success: email={} provider={}", email,
                authentication.getAuthorities());

        AuthResponse auth = authService.findOrCreateOAuth2User(email, name);

        String targetUrl = UriComponentsBuilder
                .fromUriString(oauth2Properties.getRedirectUri())
                .queryParam("accessToken", auth.accessToken())
                .queryParam("refreshToken", auth.refreshToken())
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
