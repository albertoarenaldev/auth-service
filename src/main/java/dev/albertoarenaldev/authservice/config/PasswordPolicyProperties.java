package dev.albertoarenaldev.authservice.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuracion externa de la politica de contrasenas del auth-service.
 *
 * <p>Expone el umbral minimo de score zxcvbn requerido para aceptar
 * una contrasena en {@code RegisterRequest} y {@code ResetPasswordRequest}.
 * Operativo puede endurecer o relajar la politica sin redeploy,
 * simplemente cambiando el valor en {@code application.properties} o
 * via variable de entorno (e.g. {@code APP_SECURITY_PASSWORD_POLICY_MIN_ZXCVBN_SCORE}).
 *
 * <p><b>Prefijo:</b> {@code app.security.password-policy}
 * (sigue la convencion del proyecto: ver {@link PasswordResetProperties}
 * que usa {@code app.password-reset.*} y {@code JwtProperties} en
 * {@code security/} que usa {@code app.jwt.*}).
 *
 * <p><b>Validacion al arranque:</b> el score zxcvbn es un entero
 * 0-4; valores fuera de rango fallan el arranque de la aplicacion
 * con un mensaje claro (mejor descubrirlo al deploy que en runtime).
 *
 * <p><b>Por que NO esta en el mismo {@code @ConfigurationProperties}
 * que JwtProperties:</b> cada grupo de config tiene un ciclo de vida
 * y un owner distinto. Mezclar JWT y password policy en un mismo
 * bean dificulta el mantenimiento y el versionado de la config.
 */
@ConfigurationProperties(prefix = "app.security.password-policy")
@Validated
public class PasswordPolicyProperties {

    /**
     * Score minimo de zxcvbn4j para que una contrasena sea aceptada.
     *
     * <p>Escala zxcvbn (0-4):
     * <ul>
     *   <li>0 — too guessable (top 10 mundial: "password", "1234567890")</li>
     *   <li>1 — very guessable (palabras comunes)</li>
     *   <li>2 — somewhat guessable (combinaciones)</li>
     *   <li>3 — safely unguessable (passphrases, random &gt;= 11 chars)</li>
     *   <li>4 — very unguessable (passphrases largas, random &gt;= 16 chars)</li>
     * </ul>
     *
     * <p>Default 3 (recomendado por NIST SP 800-63B para apps web
     * estandar). Bajar a 2 rompe el equilibrio UX/seguridad; subir
     * a 4 fuerza frases largas y puede frustrar a usuarios.
     */
    @Min(0)
    @Max(4)
    private int minZxcvbnScore = 3;

    public int getMinZxcvbnScore() {
        return minZxcvbnScore;
    }

    public void setMinZxcvbnScore(int minZxcvbnScore) {
        this.minZxcvbnScore = minZxcvbnScore;
    }
}
