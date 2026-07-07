package dev.albertoarenaldev.authservice.exception;

/**
 * Se lanza cuando las credenciales (email/password) proporcionadas en login
 * no son validas: email no existe, o password no coincide con el hash almacenado.
 *
 * <p>Traducida a HTTP 401 Unauthorized por
 * {@link GlobalExceptionHandler}.</p>
 *
 * <p>El mensaje es generico a proposito para no revelar al cliente si el email
 * existe o no (prevencion de user enumeration).</p>
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid credentials");
    }
}
