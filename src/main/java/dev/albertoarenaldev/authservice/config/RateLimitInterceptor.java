package dev.albertoarenaldev.authservice.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Interceptor que aplica rate limiting a endpoints anotados con
 * {@link RateLimit}.
 *
 * <p>Cada IP tiene un bucket independiente almacenado en un
 * {@link ConcurrentHashMap}. El bucket se recarga segun la config
 * de la anotacion (token-bucket algorithm via Bucket4j).
 *
 * <p>Cuando un bucket se vacia, el interceptor rechaza la peticion
 * lanzando {@link dev.albertoarenaldev.authservice.exception.RateLimitExceededException}
 * con el tiempo estimado de espera, que {@code GlobalExceptionHandler}
 * traduce a HTTP 429 + header {@code Retry-After}.
 *
 * <p>Se deshabilita con {@code app.rate-limit.enabled=false} (útil
 * para el perfil de tests, donde las peticiones comparten IP).
 *
 * <p><b>Almacenamiento in-memory:</b> adecuado para monolitos y
 * despliegues single-instance. Para entornos multi-nodo, migrar el
 * {@code ConcurrentHashMap} a un proxy JCache/Redis manteniendo la
 * misma API de Bucket4j.
 */
@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(RateLimitInterceptor.class);

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final boolean enabled;

    public RateLimitInterceptor(@org.springframework.beans.factory.annotation.Value("${app.rate-limit.enabled:true}") boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) {

        if (!enabled) {
            return true;
        }

        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RateLimit annotation = handlerMethod.getMethodAnnotation(RateLimit.class);
        if (annotation == null) {
            return true;
        }

        String ip = getClientIp(request);
        String key = annotation.name().isEmpty()
                ? ip + "@" + handlerMethod.getMethod().getName()
                : ip + "@" + annotation.name();

        Bucket bucket = buckets.computeIfAbsent(key, k -> {
            Bandwidth limit = Bandwidth.builder()
                    .capacity(annotation.capacity())
                    .refillIntervally(annotation.refillRate(),
                            Duration.ofMillis(annotation.refillUnit().toMillis(annotation.refillTime())))
                    .build();
            return Bucket.builder().addLimit(limit).build();
        });

        // Una sola llamada al bucket: tryConsumeAndReturnRemaining devuelve
        // un ConsumptionProbe con isConsumed() y getNanosToWaitForRefill().
        var probe = bucket.tryConsumeAndReturnRemaining(1);
        if (probe.isConsumed()) {
            return true;
        }

        long secondsToWait = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000L);

        log.warn("Rate limit exceeded for key={} (retry after {}s)", key, secondsToWait);

        throw new dev.albertoarenaldev.authservice.exception.RateLimitExceededException(
                "Too many requests. Please try again later.", secondsToWait);
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
