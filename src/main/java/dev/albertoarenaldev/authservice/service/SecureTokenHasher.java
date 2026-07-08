package dev.albertoarenaldev.authservice.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utilidad compartida para generar y hashear tokens opacos (refresh tokens,
 * password-reset tokens, futuros tokens de verificación de email, etc.).
 *
 * <p>Centraliza la lógica que antes vivía duplicada en
 * {@link TokenService} y {@link PasswordResetService}: ambos servicios
 * necesitan exactamente la misma generación (32 bytes {@code SecureRandom}
 * → Base64 URL-safe sin padding, 256 bits de entropía) y el mismo
 * hashing (SHA-256 hex lowercase).
 *
 * <p><b>Por qué SHA-256 (no BCrypt) para hashear tokens opacos:</b>
 * BCrypt es deliberadamente lento (~250ms) para frustrar fuerza bruta
 * sobre contraseñas débiles. Estos tokens tienen 256 bits de entropía
 * (la fuerza bruta es computacionalmente imposible), así que la
 * lentitud de BCrypt solo añadiría latencia innecesaria (~250ms) a
 * cada operación sin ganar seguridad. SHA-256 es ~1µs y suficiente.
 *
 * <p><b>Esta clase NO es un bean de Spring:</b> es utilidad pura con
 * métodos estáticos y estado JVM-global (la constante {@code SECURE_RANDOM}
 * se inicializa una sola vez al cargar la clase). Inyectarla como bean
 * sería over-engineering — no aporta nada que los métodos
 * {@code static} no aporten.
 *
 * <p><b>Thread-safety:</b> {@link SecureRandom} es thread-safe por
 * especificación. Múltiples hilos pueden invocar {@link #generateRawToken()}
 * concurrentemente sin contention. El resto de la clase no tiene estado
 * mutable.
 */
public final class SecureTokenHasher {

    /** Bytes de entropía para los tokens opacos. 32 bytes = 256 bits = 2<sup>256</sup>. */
    public static final int TOKEN_BYTES = 32;

    /**
     * {@code SecureRandom} es thread-safe y caro de construir, así que se
     * inicializa una sola vez al cargar la clase y se reutiliza siempre.
     */
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private SecureTokenHasher() {
        // Utility class — no instanciable.
    }

    /**
     * Genera un token opaco aleatorio: 32 bytes de {@code SecureRandom}
     * codificados en Base64 URL-safe sin padding (~43 caracteres,
     * 256 bits de entropía).
     *
     * <p>Es lo único que viaja al cliente (email, body JSON del login,
     * etc). La BD solo guarda el hash (ver {@link #hashToken(String)}).
     *
     * @return token en claro (Base64 URL-safe sin padding)
     */
    public static String generateRawToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Hashea el token raw con SHA-256 y devuelve representación hex
     * lowercase (64 caracteres).
     *
     * <p>Hex en vez de Base64 porque el campo en BD es {@code VARCHAR(255)}
     * y queremos legibilidad al inspeccionar logs / debugging. Hex evita
     * también problemas de collation/encoding cuando la BD compara el valor.
     *
     * @param raw token en claro
     * @return hash SHA-256 del token en hex lowercase (64 chars)
     * @throws IllegalStateException si SHA-256 no está disponible en la JVM
     *         (imposible en JVMs modernos — garantizado por spec)
     */
    public static String hashToken(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) hex.append('0');
                hex.append(h);
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 está garantizado en todas las JVMs modernas.
            throw new IllegalStateException("SHA-256 not available in this JVM", e);
        }
    }
}
