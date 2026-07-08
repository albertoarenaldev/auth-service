package dev.albertoarenaldev.authservice.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Anotacion de validacion que exige una contrasena robusta segun
 * la heuristica de zxcvbn (port Java: zxcvbn4j).
 *
 * <p>Por que existe: NIST SP 800-63B (seccion 5.1.1.2) recomienda
 * verificar las contrasenas contra listas de contrasenas comprometidas
 * o, en su defecto, contra heuristicas de fortaleza. Implementar el
 * check contra HIBP (haveibeenpwned) requiere connectivity de red y
 * parsing del API; para V1 usamos zxcvbn como proxy offline que
 * detecta patrones predecibles (palabras comunes, secuencias de
 * teclado, anos, sustituciones l33t).
 *
 * <p><b>Reglas aplicadas:</b>
 * <ul>
 *   <li>Score zxcvbn &gt;= 3 ("safely unguessable").</li>
 *   <li>Aplica a {@code RegisterRequest.password} y
 *       {@code ResetPasswordRequest.newPassword} (NIST solo exige el
 *       check en creacion/cambio, no en login).</li>
 *   <li>Si el valor es {@code null} o vacio, delega en {@code @NotBlank}.
 *       Este validador NO verifica presencia — solo calidad.</li>
 * </ul>
 *
 * <p><b>Limitaciones conocidas:</b>
 * zxcvbn4j trae por defecto diccionarios en ingles. Contrasenas
 * tipicamente hispanas (p.ej. "realmadrid123") pueden obtener un score
 * mas alto del que merecen. Para V1 aceptamos esta limitacion; V2
 * podria cargar un listado custom de contrasenas comunes en espanol.
 *
 * <p><b>Por que ConstraintValidator y no check en el service:</b>
 * (1) se integra con el {@code GlobalExceptionHandler} existente sin
 * tocar logica de negocio; (2) se ejecuta antes que el service y
 * produce 400 con field errors consistentes con el resto de
 * validaciones; (3) es declarativo en el DTO, visible para quien
 * lee el contrato.
 */
@Target({ElementType.FIELD, ElementType.PARAMETER, ElementType.RECORD_COMPONENT})
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = StrongPasswordValidator.class)
public @interface StrongPassword {

    /**
     * Mensaje de error generico por defecto. No se incluye el score
     * exacto ni detalles del feedback de zxcvbn para no exponer la
     * mecanica del scoring a un potencial atacante. La guia al usuario
     * a usar frases largas (passphrases) es suficiente y un patron
     * recomendado por NIST.
     */
    String message() default
            "La contrasena es demasiado debil. "
            + "Considera usar una frase larga con palabras no relacionadas.";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
