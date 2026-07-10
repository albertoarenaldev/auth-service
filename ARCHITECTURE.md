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
| [009](#adr-009-oauth2oidc-login-con-google-y-github) | OAuth2/OIDC login con Google y GitHub | ✅ Aceptada |
| [010](#adr-010-audit-log-sincrónico-en-base-de-datos-11-eventos) | Audit log sincrónico en base de datos (11 eventos) | ✅ Aceptada |
| [011](#adr-011-rate-limiting-en-memoria-con-bucket4j) | Rate limiting en memoria con Bucket4j | ✅ Aceptada |
| [012](#adr-012-observabilidad-con-micrometer-y-prometheus) | Observabilidad con Micrometer y Prometheus | ✅ Aceptada |

---

## ADR-001: Stack — Spring Boot 3 + Java 21

**Fecha:** 2025-07-07
**Estado:** ✅ Aceptada

### Contexto

Necesitábamos un stack moderno para un auth service que:

- Tuviera amplia adopción en la industria y ecosistema maduro de herramientas
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
- Stack consolidado: Java + Spring + JWT es la combinación con mayor documentación y ecosistema

**Negativas / trade-offs:**
- Spring Boot 3 requiere Java 17+ (OK, vamos a 21)
- Stack pesado: ~50MB de dependencias para un auth service
- Spring Security 6 cambió la API vs 5.x (curva de aprendizaje si vienes de versiones viejas)

**Alternativas consideradas:**
- **Quarkus + Java 21**: más ligero, pero con menor adopción en el ecosistema backend tradicional
- **Node.js + Express + Passport**: ecosistema JS, pero rompería la consistencia del stack Java
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

Para un auth service buscamos el equilibrio entre seguridad
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
- BCrypt es el estándar probado en el ecosistema Java con soporte nativo en Spring Security
- Strength 12 = ~250ms por hash en CPU moderna → inaceptable para ataques de fuerza bruta
- Salt automático (cada hash es único aunque el password sea el mismo)
- Compatible con hashes legacy (migración gradual a Argon2 si se quisiera)

**Negativas / trade-offs:**
- 250ms por login/register (UX) — aceptable, no perceptible
- En CPU antigua, podría ser 1-2s. Si pasa, bajar a 10
- BCrypt trunca passwords a 72 bytes silenciosamente. Para este servicio es aceptable; en un contexto enterprise se documentaría en un runbook

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
- Mayor transparencia: el código es auto-contenido y no requiere tooling adicional para su comprensión

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
- Patrón recomendado por OWASP y utilizado en la industria (Auth0, Keycloak)

**Negativas / trade-offs:**
- Más complejo que "mismo refresh token siempre"
- Si el cliente pierde el nuevo token (network error entre response y storage), tiene que re-logear
- Hay que invalidar tokens en cascada (1 query extra: `UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND id IN (...)`)

**Por qué lo implementamos en V1:**
- Es un patrón de seguridad crítico que todo dev debería conocer
- Fomenta el diseño de entidades con trazabilidad completa de auditoría
- Patron OWASP consolidado que demuestra comprension profunda de seguridad en APIs REST

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

## ADR-009: OAuth2/OIDC login con Google y GitHub

**Fecha:** 2025-07-08
**Estado:** ✅ Aceptada

### Contexto

Para reducir la fricción en el registro y mejorar la experiencia de usuario (UX), es un estándar de la industria ofrecer "Social Login". Además, delegar la autenticación a proveedores robustos reduce nuestra superficie de ataque frente a la gestión de contraseñas.

### Decisión

Implementar inicio de sesión social utilizando `spring-boot-starter-oauth2-client`:
- **Google** vía protocolo estándar OIDC (OpenID Connect).
- **GitHub** vía OAuth2 clásico.
- Flujo adaptado para enlazar cuentas sociales con correos electrónicos existentes o aprovisionar usuarios nuevos automáticamente.
- `OAuth2AuthenticationSuccessHandler` extiende `SimpleUrlAuthenticationSuccessHandler` para generar JWT + refresh token tras login exitoso y redirigir al frontend con los tokens como query params.

### Consecuencias

**Positivas:**
- Menos barreras de entrada para nuevos usuarios.
- Delegación de la seguridad de la contraseña a gigantes tecnológicos (Google/GitHub).
- Integración nativa y probada a través del ecosistema de Spring Security.
- El handler es condicional (`@ConditionalOnProperty`): se desactiva automáticamente en tests.

**Negativas / trade-offs:**
- GitHub no implementa OIDC estrictamente, lo que requiere un mapeo de atributos manual.
- Dependencia externa: si Google/GitHub caen, el login de esos usuarios también.
- Los tokens viajan como query params en la URL de redirect (patrón estándar SPA, pero visible en browser history).

**Alternativas consideradas:**
- **Auth0 / Keycloak:** Externalizar completamente la autenticación añadiendo un Identity Provider (IdP) externo. Descartado por añadir un servicio externo innecesario para un auth-service autocontenido; Spring Security OAuth2 Client nativo cubre el caso de uso sin dependencias adicionales.

---

## ADR-010: Audit log sincrónico en base de datos (11 eventos)

**Fecha:** 2025-07-08
**Estado:** ✅ Aceptada

### Contexto

Un Auth Service requiere trazabilidad estricta. Las normativas de seguridad (y buenas prácticas) exigen saber quién hizo qué, cuándo y desde dónde (IP), especialmente para eventos sensibles como intentos fallidos de login (para detectar fuerza bruta) o rotación de contraseñas.

### Decisión

Crear una entidad de dominio `AuditEvent` (almacenada en BD) alimentada de forma **sincrónica** para 11 tipos de eventos críticos: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `REGISTER`, `EMAIL_VERIFIED`, `VERIFICATION_RESENT`, `PASSWORD_CHANGED`, `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_COMPLETED`, `TOKEN_REFRESHED`, `TOKEN_REUSE_DETECTED`, `TOKENS_REVOKED`. Se captura la IP del cliente vía `RequestContextHolder`. El `AuditService` usa `Propagation.MANDATORY` para garantizar atomicidad con la transacción del caller.

### Consecuencias

**Positivas:**
- Visibilidad total y centralizada de la seguridad (útil para auditorías y bloqueos).
- Fácil de consultar vía SQL estándar sin necesitar una pila externa de logs (ELK).
- FK a User con `ON DELETE SET NULL` permite borrar usuarios sin perder el rastro de auditoría.
- Demuestra conocimientos de instrumentación y observabilidad de seguridad.

**Negativas / trade-offs:**
- Escribir logs sincrónicos añade ligera latencia (~5-10ms) a las peticiones críticas.
- Crecimiento acelerado de la tabla `audit_events`. Se requerirá una política de retención o particionado en el futuro.

**Alternativas consideradas:**
- **Colas asíncronas (Kafka / RabbitMQ):** Excelente para el rendimiento, pero requiere más infraestructura. Descartado para V1.
- **Spring Boot Actuator Audit:** El framework por defecto es menos flexible para añadir claims de dominio (como `userAgent` o IPs detrás de proxies).

---

## ADR-011: Rate limiting en memoria con Bucket4j

**Fecha:** 2025-07-08
**Estado:** ✅ Aceptada

### Contexto

Los endpoints públicos como el Login, Registro y Password Reset son vulnerables a ataques de Denegación de Servicio (DoS), enumeración de usuarios y ataques de fuerza bruta. Era imperativo establecer límites de peticiones (Rate Limiting).

### Decisión

Implementar `Bucket4j` con el algoritmo Token Bucket de forma **in-memory** mediante un interceptor de Spring MVC por dirección IP y endpoint (ej. max 5 intentos de login por minuto por IP, 3 solicitudes de forgot-password cada 5 minutos). Configurable por anotación `@RateLimit` en los métodos del controlador. Toggle global `app.rate-limit.enabled` (deshabilitado en perfil `test` para no interferir con tests existentes).

### Consecuencias

**Positivas:**
- Protección inmediata contra fuerza bruta sin requerir infraestructura extra.
- El algoritmo Token Bucket es suave y gestiona picos de tráfico (bursts) elegantemente.
- Configuración altamente personalizable por endpoint (distintos límites para login vs forgot-password).
- Respuesta 429 con header `Retry-After` sigue el estándar HTTP.

**Negativas / trade-offs:**
- El estado es in-memory local a la JVM. Si escalamos horizontalmente (varias instancias del auth-service), las cuotas no se comparten (una cuota de 5 req/min se convierte en 5 × N instancias).

**Alternativas consideradas:**
- **Redis-backed Bucket4j:** Comparte el estado en la red. Ideal, pero requiere levantar Redis. Se reserva para una V2 al evolucionar a arquitectura de microservicios con múltiples réplicas.
- **Rate limiting en API Gateway (nginx/Kong):** Mejor rendimiento general pero externaliza la lógica de control de acceso fuera del código de aplicación.

---

## ADR-012: Observabilidad con Micrometer y Prometheus

**Fecha:** 2025-07-08
**Estado:** ✅ Aceptada

### Contexto

No podemos gestionar lo que no medimos. En un entorno de producción, necesitamos monitorizar la salud del servicio, el uso de JVM (CPU, memoria), contadores de peticiones HTTP, ratios de error, y métricas de negocio (ej. logins, registros, resets de contraseña).

### Decisión

Uso de `spring-boot-starter-actuator` junto con `micrometer-registry-prometheus` para exponer un endpoint (`/actuator/prometheus`) con métricas en formato estándar de Prometheus. 8 contadores de negocio (`Counter`) definidos como beans en `MetricsConfig`: loginSuccess, loginFailure, register, emailVerified, passwordResetRequested, passwordResetCompleted, tokenRefresh, tokenReuse. Inyectados directamente en `AuthService`, `PasswordResetService` y `TokenService`.

### Consecuencias

**Positivas:**
- Estándar de facto en la industria (Cloud Native). Familiar para la mayoría de equipos DevOps/SRE (Prometheus + Grafana).
- Spring Boot Actuator autoconfigura el 90% de las métricas vitales (Tomcat threads, HikariCP pool, JVM memory).
- El modelo pull de Prometheus no satura las conexiones de salida de la aplicación.
- Contadores de negocio visibles junto a métricas de infraestructura en un solo endpoint.

**Negativas / trade-offs:**
- Riesgo de exposición de información: el endpoint `/actuator/prometheus` debe ser protegido correctamente mediante Spring Security o estar en una red/puerto de gestión aislado de internet público.

**Alternativas consideradas:**
- **Micrometer + Datadog / New Relic:** Modelos push. Más invasivos o atados a un proveedor de pago (vendor lock-in).
- **OpenTelemetry (OTel):** Más completo y moderno (métricas + trazas + logs), pero introduce sobrecarga en la configuración. Prometheus nativo es el sweet spot entre simplicidad y profesionalidad.

---

## 📝 Cómo añadir un nuevo ADR

1. Añade el siguiente correlativo a la tabla de estado (ej. `009`)
2. Crea una sección `## ADR-XXX: Título corto`
3. Rellena: **Contexto**, **Decisión**, **Consecuencias** (positivas, negativas, alternativas)
4. Cambia el estado en la tabla de arriba si aplica
5. Commit con `docs(adr): anadir ADR-XXX titulo-corto`

## ⚠️ Known limitations

### Legacy weak passwords (Fase 6 zxcvbn4j — no migra contrasenas pre-existentes)

**Contexto:** el validator `@StrongPassword` (score zxcvbn &gt;= 3) se
introdujo en el commit post-Fase 5. Aplica a
`RegisterRequest.password` y `ResetPasswordRequest.newPassword`, pero
NO a `LoginRequest.password` (NIST SP 800-63B §5.1.1.2: el check se
hace "at time of password creation or change", no en cada login).

**Limitacion:** los usuarios que se registraron con contrasenas debiles
(e.g. "Password123!", que zxcvbn puntua &lt; 3) ANTES de este fix
pueden seguir autenticandose indefinidamente. Solo quedan bloqueados
cuando intenten hacer un password reset voluntario o sean forzados a
ello.

**Por que no es critico para V1:**
- Las contrasenas de usuarios nuevos cumplen la politica desde el
  primer momento.
- Los ataques contra contrasenas debiles pre-existentes se mitigan
  por BCrypt strength 12 (costo &gt;250ms por intento, fuerza bruta
  inviable a esa escala) y por el rate limiting planeado para
  Fase 7.
- El check NO se aplica en login deliberadamente: si lo hicieramos,
  cualquier cambio de politica (subir el threshold de 3 a 4) dejaria
  a usuarios legitimos sin poder entrar.

**Mitigaciones disponibles en V1 (operativas, no automaticas):**
- Admin puede forzar un reset puntual sobre usuarios especificos
  (endpoint futuro; hoy requiere SQL directo en BD).
- En el proximo reset voluntario del usuario (olvido de contrasena),
  la nueva contrasena SI pasa por `@StrongPassword` y queda registrada
  con score &gt;= 3.

**Mitigaciones estructurales para V2 (migracion):**
- Anadir columna `password_changed_at` (Instant) a la tabla `users`.
- En el login, comparar ese timestamp contra el deploy del validator
  `@StrongPassword`: si `password_changed_at &lt; zxcvbn_introduced_at`,
  forzar reset en el siguiente login.
- Alternativa sin timestamp: un one-shot script de admin que re-hashee
  con un valor random, invalide todas las sesiones, y envie email
  de "tu cuenta fue migrada, restablece tu contrasena" a los usuarios
  con contrasena flag (no tenemos forma de evaluar zxcvbn sobre el
  bcrypt hash, asi que habria que marcar usuarios manualmente o
  basarse en un cutoff temporal).

**Decisiones alternativas consideradas:**
- Forzar validacion en login: rechazada (romperia sesiones legitimas
  al subir el threshold; NIST lo desaconseja explicitamente).
- Pedir re-validacion al usuario en el proximo login via un flag
  `requires_password_reset`: viable, marcado como "V2" porque
  requiere cambios coordinados de frontend + endpoint
  `POST /api/v1/users/me/password` (Fase 6 del roadmap original).

**Refs:** OWASP Authentication Cheat Sheet, NIST SP 800-63B §5.1.1.2,
auditoria de seguridad post-Fase 5 (hallazgo #3 cerrado para contrasenas
nuevas, abierto para legacy).

## 🧩 Plantilla

```markdown
## ADR-XXX: Título corto (verbo o sustantivo)

**Fecha:** YYYY-MM-DD
**Estado:** Propuesta | Aceptada | Deprecada | Superseded by ADR-YYY

### Contexto

Qué situación/problema llevó a la decisión. Fuerzas en juego:
- Tecnológicas
- De negocio
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
