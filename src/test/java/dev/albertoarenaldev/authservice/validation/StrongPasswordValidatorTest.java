package dev.albertoarenaldev.authservice.validation;

import com.nulabinc.zxcvbn.Zxcvbn;
import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * Tests unitarios de {@link StrongPasswordValidator} con matriz de
 * contrasenas canonicas y sus scores zxcvbn esperados.
 *
 * <p>Los scores son los reportados por zxcvbn4j 1.9.0. Si se actualiza
 * la dependencia y algunos scores cambian, ajustar las expectativas
 * (no el codigo) y documentar en el commit que version de zxcvbn4j
 * produce que scores.
 *
 * <p>El threshold activo es mutable (viene de
 * {@code PasswordPolicyConfig} en arranque). Cada test resetea el
 * threshold al default (3) en {@code @BeforeEach} para evitar
 * contaminacion entre tests.
 */
class StrongPasswordValidatorTest {

    private StrongPasswordValidator validator;
    private ConstraintValidatorContext context;

    @BeforeEach
    void setUp() {
        validator = new StrongPasswordValidator();
        // El contexto no se usa en isValid() para esta validacion (no
        // construimos mensajes custom), pero la firma lo requiere.
        context = mock(ConstraintValidatorContext.class);
        // Reset del threshold mutable: cada test arranca con el default.
        // Evita que un test que llame a setMinScore(4) contamine al
        // siguiente que asume el default 3.
        StrongPasswordValidator.setMinScore(StrongPasswordValidator.DEFAULT_MIN_SCORE);
    }

    @AfterEach
    void tearDown() {
        // Doble seguro: devolvemos el threshold al default despues de
        // cada test, por si JUnit reusa la instancia de la clase.
        StrongPasswordValidator.setMinScore(StrongPasswordValidator.DEFAULT_MIN_SCORE);
    }

    // ============================================================
    // Contrasenas debiles: score < 3 → INVALID
    // (incluye las del top 10 mundial, palabras comunes, secuencias)
    // ============================================================

    @ParameterizedTest(name = "weak password ''{0}'' (expected score < {1}) should be invalid")
    @ValueSource(strings = {
            "password",          // top 1 mundial
            "12345678",          // secuencia numerica
            "qwerty12345",       // keyboard walk + nums
            "password123",       // palabra comun + nums (sustitucion trivial)
            "iloveyou",          // palabra comun
            "abc12345",          // patron
            "admin123",          // palabra de sistema + nums
            "letmein",           // palabra comun
            "welcome01",         // palabra comun + nums
            "football2024"       // palabra + ano
    })
    @DisplayName("Contrasenas debiles (score < threshold) son rechazadas")
    void weakPasswords_areInvalid(String password) {
        int threshold = StrongPasswordValidator.getMinScore();
        assertThat(validator.isValid(password, context))
                .as("password '%s' debe ser rechazada (zxcvbn score < %d)", password, threshold)
                .isFalse();
    }

    // ============================================================
    // Contrasenas robustas: score >= 3 → VALID
    // (passphrases, random con simbolos, long-enough entropy)
    // ============================================================

    @ParameterizedTest(name = "strong password ''{0}'' (expected score >= {1}) should be valid")
    @ValueSource(strings = {
            "correct horse battery staple",   // XKCD famous passphrase
            "Tr0ub4dor&3",                    // XKCD #2: l33t + symbols + length
            "Xq8!zF2@kL9#mN5",               // random 15 chars con simbolos
            "4H#mZ!p9&Kq@nL2",                // random 14 chars alfanumerico+symbol
            "my-dog-eats-pizza-on-Tuesdays",  // passphrase con guiones
            "VientoNorteSolLunaEstrella42",    // 29 chars: palabras ES + nums
            "8x#Pq!mW2@kL7$"                  // 14 chars random
    })
    @DisplayName("Contrasenas robustas (score >= threshold) son aceptadas")
    void strongPasswords_areValid(String password) {
        int threshold = StrongPasswordValidator.getMinScore();
        assertThat(validator.isValid(password, context))
                .as("password '%s' debe ser aceptada (zxcvbn score >= %d)", password, threshold)
                .isTrue();
    }

    // ============================================================
    // Presencia: null y blank delegan en @NotBlank (return true)
    // ============================================================

    @ParameterizedTest(name = "null/blank password ''{0}'' should delegate to @NotBlank (return true)")
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Null / blank delegan en @NotBlank (no generan 'es debil')")
    void nullOrBlank_delegatesToNotBlank(String password) {
        assertThat(validator.isValid(password, context)).isTrue();
    }

    // ============================================================
    // Configurabilidad: el threshold se puede cambiar en runtime
    // (viene de app.security.password-policy.min-zxcvbn-score en
    // produccion; los tests lo cambian para verificar el efecto)
    // ============================================================

    @Test
    @DisplayName("setMinScore endurece: password con score=3 pasa con threshold 3, falla con 4")
    void configurableThreshold_strictBlocksMediumStrengthPasswords() {
        // "qwerty12345678ABC" (17 chars) tiene score zxcvbn4j 1.9.0 = 3,
        // confirmado en el boundary test del commit anterior
        // (donde "qwerty12345678ABC, 3" paso la asercion). NO usamos
        // "Tr0ub4dor&3" (XKCD canonico) porque su score es 4 en
        // zxcvbn4j 1.9.0 y pasaria con cualquier threshold valido.
        String mediumPassword = "qwerty12345678ABC";

        // Precondition: este test SOLO es significativo si el score es
        // exactamente 3. Si una version futura de zxcvbn4j cambia el
        // scoring, falla loud con un mensaje claro (no silenciosamente
        // voltea el resultado del test, que es lo que paso antes con
        // "Tr0ub4dor&3").
        int actualScore = new Zxcvbn().measure(mediumPassword).getScore();
        assertThat(actualScore)
                .as("zxcvbn4j score of '%s' debe ser exactamente 3 para que este test "
                        + "sea significativo. Si falla: zxcvbn4j cambio su scoring, "
                        + "ajustar el test (no el codigo).", mediumPassword)
                .isEqualTo(3);

        // Default 3: PASA (score 3 >= 3)
        assertThat(StrongPasswordValidator.getMinScore()).isEqualTo(3);
        assertThat(validator.isValid(mediumPassword, context))
                .as("con threshold 3 (default) la password DEBE pasar (score 3 >= 3)")
                .isTrue();

        // Endurecido a 4: FALLA (score 3 < 4)
        StrongPasswordValidator.setMinScore(4);
        assertThat(StrongPasswordValidator.getMinScore()).isEqualTo(4);
        assertThat(validator.isValid(mediumPassword, context))
                .as("con threshold 4 la misma password DEBE fallar (score 3 < 4)")
                .isFalse();

        // Relajado a 2: VUELVE A PASAR (score 3 >= 2)
        StrongPasswordValidator.setMinScore(2);
        assertThat(validator.isValid(mediumPassword, context))
                .as("con threshold 2 la password VUELVE a pasar (score 3 >= 2)")
                .isTrue();
    }

    @Test
    @DisplayName("setMinScore rechaza valores fuera de [0, 4] (zxcvbn solo tiene 5 niveles)")
    void setMinScore_rejectsOutOfRangeValues() {
        assertThatThrownBy(() -> StrongPasswordValidator.setMinScore(-1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("[0, 4]");
        assertThatThrownBy(() -> StrongPasswordValidator.setMinScore(5))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("[0, 4]");
        // El valor NO se actualiza si la entrada es invalida
        assertThat(StrongPasswordValidator.getMinScore()).isEqualTo(3);
    }
}
