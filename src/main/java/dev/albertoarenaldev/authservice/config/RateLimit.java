package dev.albertoarenaldev.authservice.config;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.concurrent.TimeUnit;

/**
 * Anotacion para proteger endpoints contra fuerza bruta y DoS
 * mediante el algoritmo token-bucket (Bucket4j).
 *
 * <p>Cada direccion IP tiene su propio bucket independiente.
 * Cuando el bucket se vacia, el interceptor {@link RateLimitInterceptor}
 * rechaza la peticion con HTTP 429 Too Many Requests.
 *
 * <p>Ejemplo de uso:
 * <pre>{@code
 * @RateLimit(capacity = 5, refillRate = 1, refillTime = 1, refillUnit = TimeUnit.MINUTES)
 * }</pre>
 * Esto permite 5 peticiones por minuto, con recarga de 1 token/min.
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {

    /** Capacidad maxima del bucket (rafagas permitidas). */
    int capacity() default 5;

    /** Cuantos tokens se reponen por {@link #refillTime} {@link #refillUnit}. */
    long refillRate() default 1;

    /** Unidad de tiempo para la recarga. */
    TimeUnit refillUnit() default TimeUnit.MINUTES;

    /** Intervalo de recarga (en la unidad definida por {@link #refillUnit}). */
    long refillTime() default 1;

    /** Clave identificadora para logs/metrics (opcional). */
    String name() default "";
}
