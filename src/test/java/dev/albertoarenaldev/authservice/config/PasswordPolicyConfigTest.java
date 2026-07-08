package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.validation.StrongPasswordValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Test de integracion que verifica el wiring end-to-end del bridge
 * pattern entre {@code application.properties} y
 * {@link StrongPasswordValidator}.
 *
 * <p>Arranca el contexto completo de Spring con la property
 * {@code app.security.password-policy.min-zxcvbn-score=4} y verifica
 * que:
 * <ol>
 *   <li>El contexto arranca sin errores (implicito: las validaciones
 *       de {@code @Min(0) @Max(4)} y el binding de
 *       {@link PasswordPolicyProperties} son correctos).</li>
 *   <li>El {@code @PostConstruct} de {@link PasswordPolicyConfig} se
 *       ejecuta y propaga el valor de la property al campo estatico
 *       del validator.</li>
 *   <li>El valor fluye en la direccion correcta: 4 (config) ->
 *       4 (validator) y NO 3 (default).</li>
 *   <li>El validator REAL (no el getter) usa el threshold aplicado:
 *       una password con score 3 debe ser rechazada con threshold 4.</li>
 * </ol>
 *
 * <p>Sin este test, los unit tests de {@code StrongPasswordValidator}
 * solo verifican el setter estatico en aislamiento. Un deploy con
 * {@code APP_SECURITY_PASSWORD_POLICY_MIN_ZXCVBN_SCORE=4} podria
 * silenciosamente quedarse con el default 3 si el wiring estuviera
 * roto (orden de @PostConstruct, @EnableConfigurationProperties
 * faltante, o binding incorrecto de properties). Este test catches
 * esos escenarios.
 *
 * <p><b>Por que {@code @DirtiesContext(AFTER_CLASS):</b> Spring cachea
 * contextos entre test classes que comparten la misma config. Sin
 * esta anotacion, una futura {@code @SpringBootTest} con
 * {@code properties="...min-zxcvbn-score=2"} reusaria este contexto
 * cacheado y su {@code @PostConstruct} NO se ejecutaria, viendo el
 * static stale en 4. {@code AFTER_CLASS} fuerza la reconstruccion del
 * contexto al terminar esta clase, garantizando que cualquier test
 * posterior empiece con un {@code @PostConstruct} fresco.
 */
@SpringBootTest(properties = "app.security.password-policy.min-zxcvbn-score=4")
@ActiveProfiles("test")
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@DisplayName("PasswordPolicyConfig end-to-end wiring")
class PasswordPolicyConfigTest {

    @Test
    @DisplayName("@PostConstruct aplica el valor de la property al campo estatico del validator")
    void postConstruct_appliesConfiguredMinScoreToValidator() {
        // El contexto arranco con properties="...min-zxcvbn-score=4",
        // PasswordPolicyConfig.applyPasswordPolicy() debio ejecutarse
        // y llamar a StrongPasswordValidator.applyMinScoreFromConfig(4).
        assertThat(StrongPasswordValidator.getMinScore())
                .as("el @PostConstruct de PasswordPolicyConfig debe haber "
                        + "aplicado el valor de la property (4) al static minScore")
                .isEqualTo(4);
    }

    @Test
    @DisplayName("El valor NO es el default (3): el wiring realmente fluye desde la property")
    void appliedValueIsNotTheDefault() {
        // Belt-and-suspenders: confirma que NO estamos viendo el valor
        // por defecto (3) por error. Si el bridge estuviera roto y el
        // static quedara en DEFAULT, este test fallaria.
        assertThat(StrongPasswordValidator.getMinScore())
                .as("el valor aplicado debe ser el de la property (4), NO el default (3)")
                .isNotEqualTo(StrongPasswordValidator.DEFAULT_MIN_SCORE)
                .isEqualTo(4);
    }

    @Test
    @DisplayName("El validator real usa el threshold aplicado (no el hardcoded)")
    void validatorUsesAppliedThresholdForIsValid() {
        // Verifica el end-to-end completo: con minScore=4, una password
        // que zxcvbn puntua con score 3 (ej. "qwerty12345678ABC") debe
        // ser RECHAZADA por isValid(), aunque pasaria con el default 3.
        // Esto confirma que el wiring no solo setea el getter, sino que
        // afecta el comportamiento real del validator.
        ConstraintValidatorContext context = mock(ConstraintValidatorContext.class);
        StrongPasswordValidator validator = new StrongPasswordValidator();
        String mediumStrengthPassword = "qwerty12345678ABC";

        // Sanity precondition: el threshold aplicado debe ser 4.
        assertThat(StrongPasswordValidator.getMinScore())
                .as("precondition: el threshold aplicado debe ser 4 por el wiring del @PostConstruct")
                .isEqualTo(4);

        // Con threshold 4 y score zxcvbn 3, isValid devuelve false.
        // Si el wiring estuviera roto y el static siguiera en 3, isValid
        // devolveria true. Esto es lo que diferencia este test del anterior
        // (test 1 solo verifica el getter; este verifica el comportamiento).
        assertThat(validator.isValid(mediumStrengthPassword, context))
                .as("con threshold 4 aplicado, la password con score zxcvbn 3 "
                        + "('qwerty12345678ABC') DEBE ser rechazada (3 < 4)")
                .isFalse();
    }
}
