package dev.albertoarenaldev.authservice.service;

import dev.albertoarenaldev.authservice.modelo.AuditEvent;
import dev.albertoarenaldev.authservice.modelo.AuditEventType;
import dev.albertoarenaldev.authservice.modelo.User;
import dev.albertoarenaldev.authservice.repository.AuditEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Servicio de auditoria: registra eventos de seguridad y negocio
 * en la tabla {@code audit_events}.
 *
 * <p>Los registros se persisten de forma sincrona con
 * {@code Propagation.MANDATORY}: exigen una transaccion existente
 * (abierta por el servicio caller). Si la operacion principal hace
 * rollback, el evento de auditoria tambien — evitando "phantom audits".
 *
 * <p>Las IPs y User-Agents se capturan en el controller y se pasan
 * como parametros. Si no estan disponibles (p.ej. en operaciones
 * internas), se dejan como {@code null}.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditEventRepository auditEventRepository;

    public AuditService(AuditEventRepository auditEventRepository) {
        this.auditEventRepository = auditEventRepository;
    }

    /**
     * Registra un evento con usuario, IP y detalles en texto libre.
     *
     * @param type     tipo de evento
     * @param user     usuario asociado (nullable para eventos sin usuario)
     * @param ip       direccion IP del cliente (nullable)
     * @param details  informacion extra (email, token id, etc.)
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEventType type, User user, String ip, String details) {
        AuditEvent event = new AuditEvent();
        event.setEventType(type);
        event.setUser(user);
        event.setIpAddress(ip);
        event.setDetails(details);
        auditEventRepository.save(event);
        log.debug("Audit: {} user={} ip={}", type, user != null ? user.getId() : null, ip);
    }

    /**
     * Registra un evento con usuario pero sin IP (operaciones internas).
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEventType type, User user, String details) {
        record(type, user, null, details);
    }

    /**
     * Registra un evento sin usuario asociado (p.ej. login fallido
     * con email inexistente).
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEventType type, String ip, String details) {
        record(type, null, ip, details);
    }

    /**
     * Registra un evento con solo detalles (sin usuario ni IP).
     * Evita ambiguedad del compilador cuando se pasa {@code null}
     * como usuario: {@code record(type, null, details)} es ambiguo
     * entre {@code (User, String)} y {@code (String, String)}.
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public void record(AuditEventType type, String details) {
        record(type, null, null, details);
    }

    /**
     * Extrae la IP del cliente del request HTTP actual via
     * {@link RequestContextHolder}. Si no hay request activo
     * (p.ej. contexto batch/test), devuelve {@code null}.
     */
    public static String getClientIp() {
        var attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) return null;
        var request = attrs.getRequest();
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}
