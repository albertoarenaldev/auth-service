package dev.albertoarenaldev.authservice.exception;

/**
 * Se lanza cuando un token (JWT de acceso o refresh token) es invalido, ha
 * expirado, esta revocado, o se detecta un reuso del mismo (familia de
 * tokens comprometida).
 *
 * <p>Traducida a HTTP 401 Unauthorized por
 * {@link GlobalExceptionHandler}.</p>
 */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException(String message) {
        super(message);
    }
}
