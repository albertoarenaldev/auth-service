package dev.albertoarenaldev.authservice.validation;

import jakarta.validation.ConstraintValidatorContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
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
 * <p>El threshold de aceptacion esta en {@link StrongPasswordValidator#MIN_SCORE}
 * (= 3). Las contrasenas con score &lt; 3 deben fallar; las que tienen
 * score &gt;= 3 deben pasar.
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
    }

    // ============================================================
    // Contrasenas debiles: score < 3 → INVALID
    // (incluye las del top 10 mundial, palabras comunes, secuencias)
    // ============================================================

    @ParameterizedTest(name = "weak password ''{0}'' (expected score < 3) should be invalid")
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
    @DisplayName("Contrasenas debiles (score < 3) son rechazadas")
    void weakPasswords_areInvalid(String password) {
        assertThat(validator.isValid(password, context))
                .as("password '%s' debe ser rechazada (zxcvbn score < %d)",
                        password, StrongPasswordValidator.MIN_SCORE)
                .isFalse();
    }

    // ============================================================
    // Contrasenas robustas: score >= 3 → VALID
    // (passphrases, random con simbolos, long-enough entropy)
    // ============================================================

    @ParameterizedTest(name = "strong password ''{0}'' (expected score >= 3) should be valid")
    @ValueSource(strings = {
            "correct horse battery staple",   // XKCD famous passphrase
            "Tr0ub4dor&3",                    // XKCD #2: l33t + symbols + length
            "Xq8!zF2@kL9#mN5",               // random 15 chars con simbolos
            "4H#mZ!p9&Kq@nL2",                // random 14 chars alfanumerico+symbol
            "my-dog-eats-pizza-on-Tuesdays",  // passphrase con guiones
            "VientoNorteSolLunaEstrella42",    // 29 chars: palabras ES + nums
            "8x#Pq!mW2@kL7$"                  // 14 chars random
    })
    @DisplayName("Contrasenas robustas (score >= 3) son aceptadas")
    void strongPasswords_areValid(String password) {
        assertThat(validator.isValid(password, context))
                .as("password '%s' debe ser aceptada (zxcvbn score >= %d)",
                        password, StrongPasswordValidator.MIN_SCORE)
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
    // Boundary: contrasenas con score exactamente = threshold
    // (punto de corte exacto del threshold)
    // ============================================================

    @ParameterizedTest(name = "boundary password ''{0}'' (expected score around threshold {1})")
    @CsvSource(value = {
            // password, expected_min_score
            "qwerty12345678ABC, 3",   // 17 chars con keyboard walk + nums + MAYUS: score real zxcvbn4j 1.9.0 = 3 (length bonus compensa patron debil)
            "Xq8!zF2@kL9, 3",         // 11 chars random con symbol: 3
            "correcthorsebatterystaple, 4"  // sin espacios, junto: 4
    })
    @DisplayName("Score exacto en el threshold (boundary)")
    void boundaryPasswords_behaveAsExpected(String password, String expectedMinScore) {
        int minScore = Integer.parseInt(expectedMinScore);
        boolean shouldBeValid = minScore >= StrongPasswordValidator.MIN_SCORE;
        assertThat(validator.isValid(password, context))
                .as("password '%s' con score esperado ~%d debe ser %s",
                        password, minScore, shouldBeValid ? "VALID" : "INVALID")
                .isEqualTo(shouldBeValid);
    }
}
