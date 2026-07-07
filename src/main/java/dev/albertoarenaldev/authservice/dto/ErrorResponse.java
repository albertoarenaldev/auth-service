package dev.albertoarenaldev.authservice.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.List;

/**
 * Cuerpo estandar de respuesta para errores HTTP de la API.
 *
 * <p>Se serializa a JSON con timestamp, status, error, message, path y, opcionalmente,
 * una lista de errores de validacion por campo. Los campos nulos se omiten del JSON
 * (gracias a {@link JsonInclude.Include#NON_NULL}) para no enviar ruido al cliente.</p>
 *
 * <p>Producido por {@link dev.albertoarenaldev.authservice.exception.GlobalExceptionHandler}
 * a partir de excepciones de dominio o de framework.</p>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        List<FieldError> fieldErrors
) {

    /**
     * Detalle de un error de validacion sobre un campo concreto del request.
     */
    public record FieldError(String field, String message) {}

    /**
     * Fabrica de ErrorResponse sin errores de validacion (errores de negocio o de sistema).
     */
    public static ErrorResponse of(int status, String error, String message, String path) {
        return new ErrorResponse(Instant.now(), status, error, message, path, null);
    }

    /**
     * Fabrica de ErrorResponse con errores de validacion por campo (errores 400 de Bean Validation).
     */
    public static ErrorResponse of(int status, String error, String message, String path, List<FieldError> fieldErrors) {
        return new ErrorResponse(Instant.now(), status, error, message, path, fieldErrors);
    }
}
