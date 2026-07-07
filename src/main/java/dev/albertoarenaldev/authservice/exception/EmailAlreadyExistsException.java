package dev.albertoarenaldev.authservice.exception;

/**
 * Se lanza cuando se intenta registrar un usuario con un email que ya existe
 * en la base de datos.
 *
 * <p>Traducida a HTTP 409 Conflict por
 * {@link GlobalExceptionHandler}.</p>
 */
public class EmailAlreadyExistsException extends RuntimeException {

    public EmailAlreadyExistsException(String email) {
        super("Ya existe un usuario con el email: " + email);
    }
}
