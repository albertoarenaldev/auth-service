package dev.albertoarenaldev.authservice.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * OAuth2 config — bindea {@code app.oauth2.*} desde application.properties.
 *
 * <p>Define la URL del frontend a la que se redirige tras un login OAuth2
 * exitoso. Los tokens JWT se pasan como query params:
 * {@code {redirectUri}?accessToken=...&refreshToken=...}
 */
@ConfigurationProperties(prefix = "app.oauth2")
@Validated
public class OAuth2Properties {

    /**
     * URL del frontend que recibe los tokens tras login OAuth2 exitoso.
     * Ejemplo: {@code http://localhost:5173/oauth2/callback}
     */
    @NotBlank
    private String redirectUri;

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
