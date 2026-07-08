package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.validation.StrongPasswordValidator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Bridge entre {@link PasswordPolicyProperties} (bean de Spring) y
 * {@link StrongPasswordValidator} (constraint validator de JSR-380
 * instanciado por el spec, NO por Spring).
 *
 * <p><b>Por que existe este bridge:</b> Jakarta Bean Validation
 * (JSR-380) exige que los {@code ConstraintValidator} sean singletons
 * instanciados por el {@code ConstraintValidatorFactory}, no por
 * Spring. Esto significa que no podemos {@code @Autowired} dependencias
 * dentro del validator. Para pasar la config externa
 * ({@code app.security.password-policy.min-zxcvbn-score}) al validator,
 * usamos un campo estatico {@code volatile} inicializado UNA vez en
 * el arranque via este {@code @Configuration}.
 *
 * <p><b>Por que constructor + {@code @PostConstruct} y no solo el
 * constructor:</b> el orden de instanciacion de los
 * {@code @Configuration} de Spring no esta garantizado antes de que
 * el contexto este listo. {@code @PostConstruct} se ejecuta DESPUES
 * de la inyeccion de dependencias y ANTES de que la aplicacion
 * acepte requests, garantizando que el valor este configurado cuando
 * llegue la primera peticion.
 */
@Configuration
@EnableConfigurationProperties(PasswordPolicyProperties.class)
public class PasswordPolicyConfig {

    private static final Logger log = LoggerFactory.getLogger(PasswordPolicyConfig.class);

    private final PasswordPolicyProperties properties;

    public PasswordPolicyConfig(PasswordPolicyProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void applyPasswordPolicy() {
        int score = properties.getMinZxcvbnScore();
        StrongPasswordValidator.setMinScore(score);
        log.info("Politica de contrasena aplicada: minZxcvbnScore={} (zxcvbn 0=trivial, 4=inquebrantable)",
                score);
    }
}
