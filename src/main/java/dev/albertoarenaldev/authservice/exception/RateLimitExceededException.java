package dev.albertoarenaldev.authservice.exception;

/**
 * Se lanza cuando un endpoint protegido por rate limiting
 * excede su cuota de peticiones. Mapeada a HTTP 429 Too Many
 * Requests por {@code GlobalExceptionHandler}.
 */
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;

    public RateLimitExceededException(String message, long retryAfterSeconds) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
