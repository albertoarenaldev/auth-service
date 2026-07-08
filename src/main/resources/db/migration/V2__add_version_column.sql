-- V2__add_version_column.sql
-- Anade la columna `version` (Hibernate @Version) a las dos entidades
-- de tokens, para optimistic locking (commit 2c47105).
--
-- Idempotente: entornos donde Hibernate ya anadio la columna via
-- ddl-auto=update (p.ej. prod tras desplegar 2c47105) la sentencia
-- se salta sin error. Combinado con baseline-on-migrate=true +
-- baseline-version=2 en application-prod.properties, las dos
-- migraciones (V1+V2) NO se ejecutan en prod; Flyway trata el
-- estado actual como V2 y solo aplica V3 en adelante.
--
-- La columna es nullable; Hibernate trata NULL como version 0, y el
-- primer UPDATE sobre cada fila la incrementa a 1.

ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS version BIGINT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS version BIGINT;
