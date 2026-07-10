package dev.albertoarenaldev.authservice.modelo;

/**
 * Tipos de eventos registrados en la tabla de auditoria.
 *
 * <p>Los nombres siguen la convencion {@code ENTIDAD_ACCION}
 * para facilitar el filtrado y la busqueda en logs/SIEM.
 */
public enum AuditEventType {

    // Auth
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    REGISTER,
    LOGOUT,

    // Email verification
    EMAIL_VERIFIED,
    VERIFICATION_RESENT,

    // Password
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,

    // Tokens
    TOKEN_REFRESHED,
    TOKEN_REUSE_DETECTED,
    TOKENS_REVOKED
}
