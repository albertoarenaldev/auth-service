package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /**
     * Invalida (marca como usado) todos los tokens de reset activos
     * (no usados, no expirados) de un usuario. Se invoca al generar un
     * nuevo token de reset para que un atacante que haya interceptado
     * un correo previo no pueda canjearlo despues de que el usuario
     * legitimo solicito uno nuevo.
     *
     * <p><b>Defensa en profundidad:</b> si el usuario pide 3 resets en
     * 5 minutos, los 3 correos se envian pero solo el ultimo token es
     * valido. La ventana de ataque contra tokens viejos se cierra en
     * cada nuevo request.
     *
     * <p>El filtro NO incluye la condicion de expiracion porque
     * {@code usedAt} es el marcador de invalidez canonico que
     * {@link PasswordResetService#resetPassword} consulta. Un token
     * expirado que no se ha usado seguira dando 401, pero marcarlo
     * explicitamente como usado limpia el conjunto de candidatos de
     * manera uniforme.
     *
     * @param userId id del usuario
     * @param now    timestamp a registrar como {@code usedAt}
     * @return numero de filas invalidadas (0 si no habia tokens activos)
     */
    @Modifying
    @Transactional
    @Query("UPDATE PasswordResetToken t SET t.usedAt = :now WHERE t.user.id = :userId AND t.usedAt IS NULL")
    int invalidateActiveTokensForUser(@Param("userId") Long userId, @Param("now") Instant now);

    /**
     * Limpieza periódica de tokens de reset expirados o usados.
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :cutoff OR t.usedAt IS NOT NULL")
    int deleteExpiredOrUsed(@Param("cutoff") Instant cutoff);
}
