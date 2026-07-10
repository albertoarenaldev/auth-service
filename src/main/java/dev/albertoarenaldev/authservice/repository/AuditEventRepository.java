package dev.albertoarenaldev.authservice.repository;

import dev.albertoarenaldev.authservice.modelo.AuditEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repositorio de eventos de auditoria. Solo operaciones de
 * escritura (save) y lectura (findAll, findByEventType, etc).
 * No hay updates ni deletes: los eventos son append-only.
 */
@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
}
