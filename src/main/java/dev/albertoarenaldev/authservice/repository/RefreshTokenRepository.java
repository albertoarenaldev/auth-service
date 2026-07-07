package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    /**
     * Busca un token que sea válido ahora mismo: existe, no revocado, no expirado.
     */
    @Query("""
            SELECT rt FROM RefreshToken rt
            WHERE rt.tokenHash = :hash
              AND rt.revokedAt IS NULL
              AND rt.expiresAt > :now
            """)
    Optional<RefreshToken> findValidByTokenHash(@Param("hash") String hash, @Param("now") Instant now);

    /**
     * Revoca todos los refresh tokens activos de un usuario (logout global,
     * cambio de contraseña, etc.).
     */
    @Modifying
    @Transactional
    @Query("""
            UPDATE RefreshToken rt
            SET rt.revokedAt = :now
            WHERE rt.user.id = :userId
              AND rt.revokedAt IS NULL
            """)
    int revokeAllByUserId(@Param("userId") Long userId, @Param("now") Instant now);

    /**
     * Limpieza periódica de tokens expirados (job programado o al arranque).
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);
}
