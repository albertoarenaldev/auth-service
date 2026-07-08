# ARCHITECTURE — auth-service

> Decisiones de arquitectura (ADR — Architecture Decision Records) del Auth Service.
> Este documento explica **por qué** el código es como es, no **cómo** funciona
> (eso está en el [README](README.md) y los Javadoc de cada clase).

---

## 📖 Cómo leer este documento

Cada ADR captura **una** decisión arquitectónica. El formato es:

- **Contexto** — qué situación/problema llevó a la decisión
- **Decisión** — qué hicimos
- **Consecuencias** — trade-offs (positivos y negativos) + alternativas consideradas

Los ADRs son **inmutables** una vez aceptados: si una decisión cambia, se escribe
un ADR nuevo que la **supersede**, no se reescribe la historia.

---

## 📋 Estado de las decisiones

| ADR | Título | Estado |
|---|---|---|
| [001](#adr-001-stack--spring-boot-3--java-21) | Stack: Spring Boot 3 + Java 21 | ✅ Aceptada |
| [002](#adr-002-jwt-híbrido--access-stateless--refresh-opaco-en-db) | JWT híbrido: access stateless + refresh opaco en DB | ✅ Aceptada |
| [003](#adr-003-bcrypt-strength-12-para-passwords) | BCrypt strength 12 para passwords | ✅ Aceptada |
| [004](#adr-004-sesiones-stateless-sin-server-side-state) | Sesiones stateless (sin server-side state) | ✅ Aceptada |
| [005](#adr-005-config-por-entorno-12-factor) | Config por entorno (12-factor) | ✅ Aceptada |
| [006](#adr-006-no-lombok--getterssetters-explícitos) | No Lombok — getters/setters explícitos | ✅ Aceptada |
| [007](#adr-007-refresh-token-rotation-con-detección-de-reuso) | Refresh token rotation con detección de reuso | ✅ Aceptada |
| [008](#adr-008-aislamiento-de-tests-con-h2--random-uuid) | Aislamiento de tests con H2 + random UUID | ✅ Aceptada |

---

## ADR-001: Stack — Spring Boot 3 + Java 21

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Necesitábamos un stack moderno para un auth service de portfolio que:

- Fuera reconocible por reclutadores (Java + Spring es el "default" en backend)
- Tuviera buena ergonomía para security (Spring Security 6 + JWT)
- Soportara Java moderno (records, pattern matching, virtual threads)
- Tuviera ecosistema maduro para JWT, JPA, testing

### Decisión

- **Java 21** (Temurin LTS, soporte hasta 2031)
- **Spring Boot 3.5.5** (autoconfig + starters)
- **Spring Security 6.x** (SecurityFilterChain API moderna)
- **JJWT 0.12.5** (generación/validación de JWTs)
- **BCrypt** (password hashing, vía Spring Security)
- **JPA + Hibernate** (persistencia, vía Spring Data)
- **H2** (dev/test) + **PostgreSQL** (prod)

### Consecuencias

**Positivas:**
- Spring Boot autoconfig ahorra ~80% del boilerplate
- Spring Security 6 con `SecurityFilterChain` bean es moderno y testeable con MockMvc
- Java 21 LTS tiene soporte a largo plazo
- JJWT 0.12.5 API es limpia (`Jwts.builder().signWith().compact()`)
- El stack es **100% estándar** — fácil de encontrar devs que lo conozcan
- Reconocible en portfolio: "sabe Java + Spring + JWT = employable"

**Negativas / trade-offs:**
- Spring Boot 3 requiere Java 17+ (OK, vamos a 21)
- Stack pesado: ~50MB de dependencias para un auth service
- Spring Security 6 cambió la API vs 5.x (curva de aprendizaje si vienes de versiones viejas)

**Alternativas consideradas:**
- **Quarkus + Java 21**: más ligero, pero menos招聘able (Spring es lo que esperan los reclutadores)
- **Node.js + Express + Passport**: ecosistema JS, pero rompería el "stack Java" del portfolio
- **Micronaut**: equilibrio, pero menos conocido

---

## ADR-002: JWT híbrido — access stateless + refresh opaco en DB

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Para autenticación con JWT hay dos estrategias canónicas:

| Estrategia | Access | Refresh | Pros | Contras |
|---|---|---|---|---|
| **A — Todo stateless** | JWT | JWT | Simple, sin DB para validar | No puedes revocar tokens hasta que expiren |
| **B — Híbrido** | JWT | Opaque en DB | Access rápido (sin DB), refresh revocable | Más complejo, refresh hace query a DB |

Para un auth service de portfolio queremos mostrar que sabemos权衡 entre seguridad
y complejidad, y que entendemos el patrón estándar de la industria (Auth0, Authentik,
Keycloak lo usan).

### Decisión

- **Access tokens**: JWT firmados (HS256), stateless, 15 min de expiración
  - Claim `sub` = email del usuario
  - Claim `roles` = array de strings (`["ROLE_USER"]`)
  - Claim `iss`, `iat`, `exp` estándar
- **Refresh tokens**: tokens opacos aleatorios (32 bytes), hasheados (SHA-256) en DB, 7 días
  - Campo `replacedByTokenId` para rotación y detección de reuso (ver ADR-007)

### Consecuencias

**Positivas:**
- Access tokens se validan sin tocar DB (rápido, ~1ms)
- Refresh tokens se pueden revocar instantáneamente (logout, robo detectado)
- 7 días de "sesión" sin que el user re-logee, pero con control total del backend
- Sigue el patrón de Auth0 / Keycloak / Authentik (lo que usa la industria)

**Negativas / trade-offs:**
- Más complejo que "todo stateless" (necesitas la entidad `RefreshToken` + repo)
- Cada refresh hace un query a DB (índice, sigue siendo rápido)
- El cliente debe guardar el refresh token de forma segura (cookie httpOnly o storage seguro)

**Por qué HS256 (no RS256):**
- **HS256** (simétrico): misma key para firmar y verificar. Simple. Bueno para monolitos.
- **RS256** (asimétrico): clave pública/privada. Bueno para microservicios donde muchos
  servicios verifican pero solo uno firma.
- Para V1 de un monolito, HS256 es lo correcto. RS256 sería over-engineering.
- Si en el futuro el proyecto se rompe en microservicios, se puede migrar a RS256
  con breaking change controlado (los access tokens emitidos con HS256 dejarían de
  funcionar, pero caducan en 15 min).

---

## ADR-003: BCrypt strength 12 para passwords

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Spring Security ofrece varios `PasswordEncoder`s:

- **BCrypt**: estándar de facto, lento a propósito (~250ms por hash a strength 12)
- **Argon2**: ganador del Password Hashing Competition, más seguro en hardware moderno
- **PBKDF2**: legacy, NIST-recomendado
- **SCrypt**: similar a BCrypt con parámetros ajustables

### Decisión

**`BCryptPasswordEncoder(12)`** — strength 12 (default de Spring Security 6).

### Consecuencias

**Positivas:**
- BCrypt es lo que esperan ver los reclutadores en un portfolio Java
- Strength 12 = ~250ms por hash en CPU moderna → inaceptable para暴力破解
- Salt automático (cada hash es único aunque el password sea el mismo)
- Compatible con hashes legacy (migración gradual a Argon2 si se quisiera)

**Negativas / trade-offs:**
- 250ms por login/register (UX) — aceptable, no perceptible
- En CPU antigua, podría ser 1-2s. Si pasa, bajar a 10
- BCrypt trunca passwords a 72 bytes silenciosamente. Para portfolio OK; para
  enterprise documentar en un FAQ

**Por qué no Argon2:**
- Argon2 es más seguro técnicamente, pero menos conocido en Java
- Spring lo soporta (`Argon2PasswordEncoder`), pero el "go-to" sigue siendo BCrypt
- Si en el futuro quieres migrar: el `PasswordEncoder` es un bean, lo cambias en
  1 línea y los nuevos hashes son Argon2; los viejos los re-hasheas en el próximo login

**Alternativas consideradas:**
- **Argon2**: más seguro técnicamente, pero menos conocido en Java
- **SCrypt**: similar a BCrypt pero menos soporte en Spring

---

## ADR-004: Sesiones stateless (sin server-side state)

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Spring Security por defecto usa sesiones HTTP (cookie `JSESSIONID`). Para una API REST
con JWT, queremos sesiones **stateless** (sin estado en el servidor).

### Decisión

- `SessionCreationPolicy.STATELESS`
- CSRF deshabilitado (no hay sesiones que proteger)
- Sin cookies, solo `Authorization: Bearer XXX` header
- El `SecurityContext` NO se persiste entre requests (cada request trae su propio JWT)

### Consecuencias

**Positivas:**
- API REST pura, sin estado en el servidor
- Escalable horizontalmente sin sticky sessions
- CSRF no aplica (no hay cookies)
- Compatible con cualquier cliente (web, mobile, CLI, server-to-server)

**Negativas / trade-offs:**
- No puedes invalidar un JWT antes de su expiración → mitigado con refresh token rotation (ADR-007)
- El cliente debe guardar el JWT de forma segura (XSS vulnerable si se guarda en `localStorage`)
- Para apps web: access en memoria, refresh en cookie `httpOnly + Secure + SameSite=Strict`

**Cuándo reconsiderar:**
- Si en el futuro se necesita "logout instantáneo de todos los JWTs activos", se
  necesitaría un blacklist de `jti` (JWT ID) en Redis. Por ahora, no es requisito.

---

## ADR-005: Config por entorno (12-factor)

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

El proyecto necesita funcionar en 3 entornos (dev, test, prod) con configs diferentes.
El código no debe contener valores específicos de entorno (12-factor app methodology).

### Decisión

- **Spring profiles**: `dev`, `test`, `prod` (default: `dev`)
- **`application-{profile}.properties`** para overrides por perfil
- **Secrets vía env vars**: `${JWT_SECRET:default-dev}`, `${SPRING_DATASOURCE_PASSWORD:}`
- **Ningún secret hardcoded** en el código (auditado con grep antes del primer push)
- **`@ConfigurationProperties`** para bindear grupos de config (`JwtProperties` para `app.jwt.*`)
- **Validación al arrancar** con `@Validated` + `@NotBlank` + `@NotNull` + `@Positive`

### Consecuencias

**Positivas:**
- 12-factor app: misma imagen (jar) corre en dev, test, prod
- Secrets fuera del código (en env vars o vault en prod)
- Config validada al arrancar → no falla en runtime con `NullPointerException`
- Test profile aislado y reproducible (H2 con UUID random)

**Negativas / trade-offs:**
- Más perfiles que mantener (4 archivos `.properties`)
- Si alguien sube un secret por error, se filtra → mitigado con `.gitignore` + auditoría pre-push
- El default profile es `dev` (no `prod`) por seguridad. Documentado en README.

**Secretos del test profile:**
- El JWT secret del test profile es claramente fake: `test-only-secret-do-not-use-in-production-32bytes-min-ok`
- Sirve para que JJWT tenga un secret ≥32 bytes (HS256 requirement) y los tests pasen

---

## ADR-006: No Lombok — getters/setters explícitos

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Lombok genera getters/setters/constructors en compile-time vía anotaciones
(`@Getter`, `@Setter`, `@Data`, `@Builder`). Reduce ~40% de líneas de código.
Spring Boot ecosystem lo usa masivamente (es el default en muchos starters).

### Decisión

**No Lombok.** Getters/setters explícitos con Javadoc en los campos importantes.

### Consecuencias

**Positivas:**
- Sin magia: ves el getter/setter literal en el código
- No necesitas plugin de IDE para Lombok
- El proyecto se compila con `javac` puro (sin annotation processors)
- Consistencia con proyecto hermano `gestion-eventos` (mismo autor, misma regla)
- Mejor para portfolio: muestra que entiendes los fundamentos del lenguaje

**Negativas / trade-offs:**
- ~30% más líneas de código en las entities (User tiene 200 líneas vs ~120 con Lombok)
- Boilerplate repetitivo (especialmente en entities con 8+ campos)

**Cuándo reconsiderar:**
- Si el proyecto crece a 20+ entities y el boilerplate empieza a doler
- En ese punto, evaluar Lombok de nuevo (con `@Data` para entities, `@Value` para DTOs)
- Por ahora: legibilidad > brevedad

---

## ADR-007: Refresh token rotation con detección de reuso

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Los refresh tokens tienen un riesgo: si un atacante los roba (XSS, malware, logs
expuestos, etc.), puede usarlos indefinidamente hasta que expiren.

**Token rotation** es la técnica estándar:
- Cada vez que el cliente usa un refresh token, se emite uno nuevo y el viejo se marca como "reemplazado"
- Si el viejo se vuelve a usar, es señal de robo → invalidar toda la familia

Es el patrón que usan Auth0, Authentik, Keycloak, y recomienda OWASP.

### Decisión

La entidad `RefreshToken` tiene un campo `replacedByTokenId` (nullable Long).

**Flujo de rotación normal:**

```
1. Cliente presenta RT1
2. Servidor valida RT1 (no expirado, no revocado)
3. Servidor crea RT2 nuevo y marca RT1.revokedAt = NOW(), RT1.replacedByTokenId = RT2.id
4. Servidor devuelve { accessToken (nuevo), refreshToken: RT2 }
5. Cliente guarda RT2
```

**Flujo de detección de reuso:**

```
1. Cliente presenta RT1 (que ya fue rotado a RT2)
2. Servidor ve RT1.revokedAt != null → falla validación
3. PERO ADEMÁS: el servidor sabe que pasó algo raro (RT1 fue robado o el cliente tiene
   un bug), así que invalida TODA la familia de RTs del usuario:
   - RT1 (ya está revocado)
   - RT2 (que reemplazó a RT1) — puede que también esté comprometida
4. Log de seguridad event
5. Cliente tiene que re-logear
```

### Consecuencias

**Positivas:**
- Detección proactiva de robo de tokens
- Fuerza al usuario a re-logear si pasa algo raro (visible para ellos)
- Es el patrón recomendado por OWASP y la industria
- Diferenciador en entrevistas ("¿cómo manejas el reuso de refresh tokens?")

**Negativas / trade-offs:**
- Más complejo que "mismo refresh token siempre"
- Si el cliente pierde el nuevo token (network error entre response y storage), tiene que re-logear
- Hay que invalidar tokens en cascada (1 query extra: `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND id IN (...)`)

**Por qué lo implementamos en V1:**
- Es un patrón de seguridad crítico que todo dev debería conocer
- Enseña a diseñar entidades con campos de auditoría
- Diferenciador fuerte en portfolio

---

## ADR-008: Aislamiento de tests con H2 + random UUID

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Tests JPA que comparten la misma DB en memoria tienen problemas:

- Tests creando rows que se ven entre sí
- Estado residual entre tests
- Violaciones de PK si el seed (`DataSeeder`) corre en cada contexto de test
- Tests en paralelo (Surefire fork) pueden tener colisiones

### Decisión

- **H2 in-memory con nombre aleatorio**: `jdbc:h2:mem:testdb-${random.uuid}`
- **`@DataJpaTest`**: cada test class tiene su propio contexto Spring → su propia DB H2
- **`@SpringBootTest`** (smoke, DataSeederTest, SecurityConfigTest): mismo profile `test`
- **`DB_CLOSE_DELAY=-1`**: la DB se mantiene viva mientras la JVM esté arriba
- **`spring.sql.init.mode=never`** + **`defer-datasource-initialization=false`**: doble seguro contra `import.sql` accidentales

### Consecuencias

**Positivas:**
- Tests 100% aislados (cada uno su propia DB)
- No hay riesgo de "test pollution" entre clases
- Reproducible (mismas fixtures en cada run)
- El smoke test + DataSeederTest + SecurityConfigTest pueden correr juntos sin interferir
- Funciona con tests en paralelo (`@Fork` de Surefire)

**Negativas / trade-offs:**
- H2 no es 100% compatible con PostgreSQL (diferencias menores en SQL, tipos)
- Si quieres validar "PostgreSQL-specific features" (JSONB, array columns, etc.),
  necesitas **Testcontainers** con PostgreSQL real
- Para V1, H2 es suficiente; V2+ podría añadir Testcontainers como dependencia opt-in

**Por qué `random.uuid` y no un counter (`testdb-1`, `testdb-2`):**
- Con `@Fork` de Surefire, varios tests pueden correr en paralelo en la misma JVM
- Un counter tendría colisiones; el UUID no
- `${random.uuid}` lo resuelve Spring al cargar la property (cada contexto obtiene uno nuevo)

---

## 📝 Cómo añadir un nuevo ADR

1. Añade el siguiente correlativo a la tabla de estado (ej. `009`)
2. Crea una sección `## ADR-XXX: Título corto`
3. Rellena: **Contexto**, **Decisión**, **Consecuencias** (positivas, negativas, alternativas)
4. Cambia el estado en la tabla de arriba si aplica
5. Commit con `docs(adr): anadir ADR-XXX titulo-corto`

## 🧩 Plantilla

```markdown
## ADR-XXX: Título corto (verbo o sustantivo)

**Fecha:** YYYY-MM-DD
**Estado:** Propuesta | Aceptada | Deprecada | Superseded by ADR-YYY

### Contexto

Qué situación/problema llevó a la decisión. Fuerzas en juego:
- Tecnológicas
- De negocio
- De equipo / portfolio
- De tiempo

### Decisión

Qué decidimos hacer. Concreto, no abstracto.

### Consecuencias

**Positivas:**
- ...

**Negativas / trade-offs:**
- ...

**Alternativas consideradas:**
- ...
```
