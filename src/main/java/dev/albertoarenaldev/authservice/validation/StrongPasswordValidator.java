package dev.albertoarenaldev.authservice.validation;

import com.nulabinc.zxcvbn.Zxcvbn;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import org.springframework.stereotype.Component;

/**
 * Validador de fortaleza de contrasena basado en zxcvbn4j (port Java
 * de la libreria zxcvbn de Dropbox).
 *
 * <p><b>Threshold score &gt;= 3:</b> "safely unguessable" segun la
 * escala de zxcvbn. Bloquea la gran mayoria de contrasenas debiles
 * (palabras comunes, secuencias de teclado, anos, sustituciones l33t)
 * sin necesidad de frases de 4+ palabras que exige el score 4. Es
 * el equilibrio UX/seguridad recomendado para apps web estandar.
 *
 * <p><b>Score 0-4 zxcvbn:</b>
 * <pre>
 * 0 — too guessable: top 10 passwords, "password", "1234567890"
 * 1 — very guessable: passwords del top 10^4, palabras comunes
 * 2 — somewhat guessable: combinaciones de palabras + numeros/l33t
 * 3 — safely unguessable: passphrases de 4 palabras, contrasenas random &gt;= 11 chars
 * 4 — very unguessable: passphrases largas, contrasenas random &gt;= 16 chars
 * </pre>
 *
 * <p><b>Por que la instancia de {@link Zxcvbn} es final y se crea
 * una sola vez:</b> el constructor de {@code Zxcvbn} carga los
 * diccionarios (~20MB) desde el classpath. Spring instancia este
 * validador como singleton (los {@code ConstraintValidator} lo son
 * por contrato de Jakarta Bean Validation), asi que el cost de
 * carga se paga una sola vez al arrancar el contexto, no por cada
 * request.
 *
 * <p><b>Por que delega en {@code @NotBlank} para presencia:</b> este
 * validador se enfoca en CALIDAD. Si el campo es null o vacio, retorna
 * {@code true} para que el mensaje de error provenga de la anotacion
 * de presencia (mas claro: "el campo es obligatorio") en vez de
 * mezclarse con el de calidad ("la contrasena es debil").
 */
@Component
public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    /**
     * Score minimo aceptado. 3 = "safely unguessable".
     * Constante publica para que los tests y la documentacion la
     * referencien sin magic numbers.
     */
    public static final int MIN_SCORE = 3;

    /**
     * Motor zxcvbn. La instancia es thread-safe segun el README de
     * zxcvbn4j (no mantiene estado mutable entre measure() calls).
     * Como este validador es singleton, todos los threads del pool
     * HTTP comparten esta misma instancia.
     */
    private final Zxcvbn zxcvbn = new Zxcvbn();

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // Presencia: lo maneja @NotBlank. Aceptamos null/blank aqui
        // para que el mensaje de error sea "obligatorio" y no "debil".
        if (value == null || value.isBlank()) {
            return true;
        }
        int score = zxcvbn.measure(value).getScore();
        return score >= MIN_SCORE;
    }
}
