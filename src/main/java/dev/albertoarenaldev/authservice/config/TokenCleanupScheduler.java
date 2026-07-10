package dev.albertoarenaldev.authservice.config;

import dev.albertoarenaldev.authservice.repository.EmailVerificationTokenRepository;
import dev.albertoarenaldev.authservice.repository.PasswordResetTokenRepository;
import dev.albertoarenaldev.authservice.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Job programado de limpieza de tokens expirados o usados.
 *
 * <p>Previene la acumulacion indefinida de filas en las tablas
 * {@code refresh_tokens}, {@code password_reset_tokens} y
 * {@code email_verification_tokens}. Se ejecuta cada hora
 * (cron {@code 0 0 * * * *}) y en cada arranque de la aplicacion
 * ({@code initialDelay = 30s}) para limpiar tokens acumulados
 * durante paradas.
 *
 * <p>Cada DELETE tiene su propio {@code @Transactional} para que
 * un fallo en una tabla no haga rollback de las limpiezas ya
 * exitosas en otras tablas.
 *
 * <p>Deshabilitado en el perfil {@code test} (no hay ventanas de
 * tiempo largas en tests como para que importe la acumulacion).
 */
@Component
@Profile("!test")
@EnableScheduling
public class TokenCleanupScheduler {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupScheduler.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailVerificationTokenRepository emailVerificationTokenRepository;

    public TokenCleanupScheduler(RefreshTokenRepository refreshTokenRepository,
                                 PasswordResetTokenRepository passwordResetTokenRepository,
                                 EmailVerificationTokenRepository emailVerificationTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.emailVerificationTokenRepository = emailVerificationTokenRepository;
    }

    /**
     * Limpia tokens expirados/usados cada hora y al arrancar.
     * El {@code initialDelayString} de 30s da tiempo a Flyway a
     * aplicar migraciones pendientes antes del primer DELETE.
     */
    @Scheduled(cron = "0 0 * * * *")
    @Scheduled(initialDelayString = "PT30S", fixedDelayString = "PT1H")
    @Transactional
    public void cleanupExpiredTokens() {
        Instant cutoff = Instant.now();
        int deleted = 0;

        int refresh = refreshTokenRepository.deleteExpired(cutoff);
        deleted += refresh;

        int reset = passwordResetTokenRepository.deleteExpiredOrUsed(cutoff);
        deleted += reset;

        int verification = emailVerificationTokenRepository.deleteExpiredOrUsed(cutoff);
        deleted += verification;

        if (deleted > 0) {
            log.info("Token cleanup: {} rows deleted (refresh={}, password-reset={}, email-verification={})",
                    deleted, refresh, reset, verification);
        }
    }
}
