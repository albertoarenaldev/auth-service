package dev.albertoarenaldev.authservice.validation;

import com.nulabinc.zxcvbn.Zxcvbn;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

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
 * <p><b>Por que NO es un {@code @Component} de Spring:</b> Jakarta
 * Bean Validation (JSR-380, seccion 3.4.2) exige que los
 * {@code ConstraintValidator} sean singletons instanciados por el
 * {@code ConstraintValidatorFactory} del contenedor, no por Spring.
 * Esto significa que no se puede usar {@code @Autowired} ni otras
 * anotaciones de Spring dentro del validator. La instanciacion es
 * responsabilidad del framework, que garantiza el singleton.
 *
 * <p><b>Como llega la config ({@code app.security.password-policy.min-zxcvbn-score})
 * al validator:</b> a traves de un campo estatico
 * {@code volatile} inicializado UNA sola vez en el arranque de la
 * aplicacion por {@code PasswordPolicyConfig} (que SI es un bean de
 * Spring, puede inyectar la {@code @ConfigurationProperties} y llama
 * al setter estatico). El modificador {@code volatile} garantiza
 * visibilidad entre threads (cualquier cambio de configuracion se
 * propaga a todos los threads que sirven requests).
 *
 * <p><b>Por que la instancia de {@link Zxcvbn} es final:</b> el
 * constructor de {@code Zxcvbn} carga los diccionarios (~20MB)
 * desde el classpath. El contrato singleton del JSR-380 garantiza
 * que este constructor se invoca UNA sola vez por clase validator
 * (no por cada peticion), asi que el cost de carga se paga una
 * vez al instanciar el validator.
 *
 * <p><b>Por que delega en {@code @NotBlank} para presencia:</b> este
 * validador se enfoca en CALIDAD. Si el campo es null o vacio, retorna
 * {@code true} para que el mensaje de error provenga de la anotacion
 * de presencia (mas claro: "el campo es obligatorio") en vez de
 * mezclarse con el de calidad ("la contrasena es debil").
 */
public class StrongPasswordValidator implements ConstraintValidator<StrongPassword, String> {

    /**
     * Valor por defecto del umbral zxcvbn (3 = "safely unguessable").
     * Se usa como fallback si {@link PasswordPolicyConfig} no consigue
     * aplicar la config externa (e.g. en tests que no arrancan el
     * contexto de Spring).
     */
    public static final int DEFAULT_MIN_SCORE = 3;

    /**
     * Umbral activo. Inicializado al default; {@code PasswordPolicyConfig}
     * lo sobreescribe en el arranque con el valor de
     * {@code app.security.password-policy.min-zxcvbn-score}. El modificador
     * {@code volatile} garantiza visibilidad cross-thread: un cambio en
     * runtime (poco probable pero posible via reconfiguracion dinamica)
     * se propaga a todos los threads inmediatamente.
     */
    private static volatile int minScore = DEFAULT_MIN_SCORE;

    /**
     * Motor zxcvbn. La instancia es thread-safe segun el README de
     * zxcvbn4j (no mantiene estado mutable entre measure() calls).
     * Como este validator es singleton por contrato del JSR-380,
     * todos los threads del pool HTTP comparten esta misma instancia.
     */
    private final Zxcvbn zxcvbn = new Zxcvbn();

    /**
     * Devuelve el umbral activo. Pensado para uso en tests (assertion
     * messages) y para tooling/debug. NO usar como API publica desde
     * otros servicios: el umbral es decision interna del validator.
     */
    public static int getMinScore() {
        return minScore;
    }

    /**
     * Establece el umbral activo. Pensado para que
     * {@code PasswordPolicyConfig} lo invoque en el arranque. Tambien
     * lo usan los tests que quieren verificar el comportamiento con
     * un threshold custom (e.g. setMinScore(4) para probar que
     * passphrases de 4 palabras que pasan con threshold 3 ahora
     * fallan con threshold 4).
     *
     * @param score nuevo umbral, debe estar en [0, 4]
     * @throws IllegalArgumentException si score esta fuera de rango
     */
    public static void setMinScore(int score) {
        if (score < 0 || score > 4) {
            throw new IllegalArgumentException(
                    "minZxcvbnScore debe estar en [0, 4], se recibio: " + score);
        }
        minScore = score;
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        // Presencia: lo maneja @NotBlank. Aceptamos null/blank aqui
        // para que el mensaje de error sea "obligatorio" y no "debil".
        if (value == null || value.isBlank()) {
            return true;
        }
        int score = zxcvbn.measure(value).getScore();
        return score >= minScore;
    }
}
