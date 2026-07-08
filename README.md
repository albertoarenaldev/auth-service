# auth-service

[![CI](https://github.com/albertoarenaldev/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/albertoarenaldev/auth-service/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.5-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen)](#)
[![Branches](https://img.shields.io/badge/branches-89%25-green)](#)
[![Tests](https://img.shields.io/badge/tests-100%2F100-brightgreen)](#)

> Auth Service — stateless JWT authentication built with Spring Boot 3 + Spring Security 6.
> Designed as a portfolio project showcasing clean architecture, testable security, and 12-factor config.

---

## 📑 Tabla de contenidos

- [Estado del proyecto](#-estado-del-proyecto)
- [Stack](#-stack)
- [Arquitectura](#-arquitectura)
- [Endpoints](#-endpoints)
- [Desarrollo local](#-desarrollo-local)
  - [Con Docker Compose (recomendado)](#-con-docker-compose-recomendado)
- [Tests](#-tests)
- [CI / Deployment](#-ci--deployment)
- [Estructura del proyecto](#-estructura-del-proyecto)
- [Roadmap](#-roadmap)
- [Contribuir](#-contribuir)
- [Licencia](#-licencia)

---

## 📊 Estado del proyecto

| Fase | Estado | Descripción |
|---|---|---|
| **Fase 1** — Setup | ✅ | Spring Boot 3.5.5 + Java 21 + JPA + H2 + PostgreSQL + JJWT + BCrypt |
| **Fase 2** — Data model | ✅ | User, Role, RefreshToken, PasswordResetToken + tests (13 tests) |
| **Fase 3** — Security infra | ✅ | JwtProperties, JwtTokenProvider, JwtAuthenticationFilter, JwtAuthenticationEntryPoint, SecurityConfig, PasswordEncoderConfig (16 tests) |
| **Fase 4** — Endpoints | ✅ | register, login, refresh, logout + TokenService con rotacion, reuse detection y revocacion de familia (15 tests nuevos: 7 integracion + 8 unitarios) |
| **Fase 5** — Password reset + hardening | ✅ | Flujo completo con email token + endpoint público + NIST zxcvbn + optimistic locking en tokens |
| **Fase 6** — User profile | ⏳ | `GET/PUT /api/v1/users/me`, change password |

**Tests:** 100/100 verde · **Cobertura:** 95% line · 89% branch · 100% class (JaCoCo 0.8.11 sobre `mvn verify`) · **Java:** 21 · **Spring Boot:** 3.5.5

---

## 🧰 Stack

| Capa | Tecnología |
|---|---|
| Lenguaje | Java 21 (Temurin) |
| Framework | Spring Boot 3.5.5 |
| Seguridad | Spring Security 6.x, JJWT 0.12.5 (HS256), BCrypt strength 12 |
| Persistencia | JPA + Hibernate, H2 (dev/test), PostgreSQL (prod) |
| Migraciones | Flyway 10+ (`V1__init_schema.sql`, `V2__add_version_column.sql`) + `ddl-auto: validate` |
| Política de contraseña | zxcvbn4j 1.9.0 — NIST SP 800-63B (threshold score ≥ 3, configurable por `@ConfigurationProperties`) |
| Build | Maven 3.9+ |
| Tests | JUnit 5, AssertJ, MockMvc, @DataJpaTest |
| Mail | Spring Mail (JavaMailSender) + MailHog (dev) |
| CI | GitHub Actions (Ubuntu + Temurin JDK 21) |
| Contenedores | Docker (multi-stage) + Docker Compose (PostgreSQL 16 + MailHog) |
| Config | 12-factor (env vars, perfiles Spring) |

---

## 🏛️ Arquitectura

**Capas y flujo de un request autenticado:**

```
┌─────────────────────────────────────────────────────────────┐
│  HTTP request                                                │
│      ↓                                                       │
│  SecurityFilterChain                                          │
│      ↓                                                       │
│  JwtAuthenticationFilter                                      │
│  ├─ extract "Authorization: Bearer XXX"                       │
│  ├─ validate token (JwtTokenProvider)                         │
│  └─ populate SecurityContext (email + roles)                  │
│      ↓                                                       │
│  AuthorizationFilter (¿autenticado?)                          │
│      ↓ si NO                                                 │
│  JwtAuthenticationEntryPoint                                  │
│  └─ 401 + JSON body + header WWW-Authenticate: Bearer        │
│      ↓ si SÍ                                                 │
│  AuthController (placeholder) → 200                           │
└─────────────────────────────────────────────────────────────┘

Beans inyectados:
  SecurityConfig
    ├─ JwtAuthenticationFilter ─→ JwtTokenProvider ─→ JwtProperties
    └─ JwtAuthenticationEntryPoint ─→ ObjectMapper (Jackson)

Validación de tokens:
  JwtTokenProvider
    ├─ Keys.hmacShaKeyFor(secret)       ← 32+ bytes, HS256
    ├─ Jwts.builder().signWith(key)     ← genera
    └─ Jwts.parser().verifyWith(key)    ← valida firma + expiración

Claims del JWT:
  - sub: email del usuario
  - iss: auth-service (configurable)
  - iat / exp: timestamps
  - roles: ["ROLE_USER", "ROLE_ADMIN", ...]
```

**Decisiones de diseño clave:**

- **Access tokens son JWT stateless** (HS256, 15 min default).
- **Refresh tokens son opacos y viven en DB** (`RefreshToken` entity) — permite revocación inmediata y detección de reuso de tokens robados.
- **Contraseñas hasheadas con BCrypt** strength 12 (~250ms por hash).
- **Config por entorno (12-factor)**: secretos vía env vars, nunca hardcoded.
- **Sesiones stateless**: CSRF deshabilitado, `SessionCreationPolicy.STATELESS`.
- **CORS configurable** desde `app.cors.origins` (CSV) — sensible a entornos.

---

## 🌐 Endpoints

### Implementados (V1)

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `GET` | `/api/v1/auth/health` | público | Health check del módulo auth. Devuelve `{"status":"UP"}` |
| `POST` | `/api/v1/auth/register` | público | Crear cuenta: `{email, password, firstName, lastName}` → 201 + `{accessToken, refreshToken, user}` |
| `POST` | `/api/v1/auth/login` | público | Login: `{email, password}` → 200 + `{accessToken, refreshToken, user}`. 401 generico para evitar user enumeration |
| `POST` | `/api/v1/auth/refresh` | público | Rotar refresh token: `{refreshToken}` → 200 + nuevos tokens. Deteccion de reuso + revocacion de familia |
| `POST` | `/api/v1/auth/logout` | público | Revocar refresh token: `{refreshToken}` → 204 No Content. Idempotente |
| `POST` | `/api/v1/auth/forgot-password` | público | Solicitar email de reset: `{email}` → 202 Accepted (devuelve 202 exista o no el email, anti-enumeración) |
| `POST` | `/api/v1/auth/reset-password` | público | Confirmar reset: `{token, newPassword}` → 204 No Content. Token hasheado SHA-256, un solo uso, expira en 15 min |
| `GET` | `/actuator/health` | público | Health check agregado (DB, disk, mail) |
| `GET` | `/actuator/info` | 🔒 autenticado | Metadata del build (protegido para evitar info leak) |

### Planificados (V1.1)

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `GET` | `/api/v1/users/me` | 🔒 autenticado | Perfil del usuario actual |
| `PUT` | `/api/v1/users/me` | 🔒 autenticado | Actualizar perfil |
| `POST` | `/api/v1/users/me/password` | 🔒 autenticado | Cambiar contraseña |

**Formato de respuesta 401 (RFC 6750):**
```json
{
  "timestamp": "2025-07-07T12:34:56.789Z",
  "status": 401,
  "error": "Unauthorized",
  "message": "...",
  "path": "/api/v1/..."
}
```
Header `WWW-Authenticate: Bearer realm="auth-service"` siempre presente en 401.

---

## 💻 Desarrollo local

Tienes dos formas de arrancar el proyecto en local:

- **🐳 Con Docker Compose (recomendado)** — un único comando levanta la app + PostgreSQL 16 + MailHog.
- **☕ Sin Docker** — solo necesitas Java 21 y Maven 3.9+; usa H2 en memoria en vez de PostgreSQL.

### 🐳 Con Docker Compose (recomendado)

**Requisitos:** solo [Docker](https://docs.docker.com/get-docker/) (Docker Desktop o el engine de Linux). No necesitas Java, ni Maven, ni PostgreSQL local.

**Setup (un solo comando):**

```bash
git clone https://github.com/albertoarenaldev/auth-service.git
cd auth-service
docker compose up --build
```

La primera vez tarda 1-2 minutos (descarga imágenes de Maven/Temurin/Postgres/MailHog y compila el jar). Las siguientes son instantáneas gracias a la cache de capas de Docker y a la cache de dependencias Maven separada.

**Qué se levanta:**

| Servicio | Puerto | URL | Credenciales |
|---|---|---|---|
| `auth-service` (Spring Boot) | 8080 | http://localhost:8080 | — |
| `postgres` (PostgreSQL 16) | 5432 | `jdbc:postgresql://localhost:5432/authdb` | `authuser` / `authpass` / db `authdb` |
| `mailhog` (SMTP fake + Web UI) | 1025 / 8025 | SMTP en `localhost:1025` · Web UI en http://localhost:8025 | sin auth |

**Comandos útiles:**

```bash
# Ver logs de la app (follow)
docker compose logs -f auth-service

# Ver logs de un servicio concreto
docker compose logs -f postgres

# Parar todo (conserva el volumen de postgres con tus datos)
docker compose down

# Parar todo Y borrar el volumen de postgres (reset completo)
docker compose down -v

# Entrar a un contenedor para debug
docker compose exec auth-service sh
docker compose exec postgres psql -U authuser -d authdb

# Rebuild de la app tras cambiar codigo
docker compose up --build auth-service
```

**Cómo sabe la app que use PostgreSQL y MailHog:** el `docker-compose.yml` fija `SPRING_PROFILES_ACTIVE=prod` y sobreescribe los parámetros de mail para apuntar a MailHog (sin auth, sin TLS). El resto de la configuración (datasource URL, credenciales, JWT secret) también viene del compose vía env vars (12-factor).

> ⚠️ **Las credenciales y `JWT_SECRET` del `docker-compose.yml` son valores de DESARROLLO.** Para producción, regenera el secret con `openssl rand -base64 48` y externaliza las credenciales de PostgreSQL/SMTP a tu plataforma de despliegue.

### ☕ Sin Docker

Si prefieres correr la app directamente con Maven (más rápido para iterar en desarrollo, pero sin PostgreSQL ni MailHog):

**Requisitos:** Java 21 (Temurin) y Maven 3.9+.

```bash
git clone https://github.com/albertoarenaldev/auth-service.git
cd auth-service

# Levanta la app con perfil `dev` (H2 en memoria + sin mail real)
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

La app arranca en `http://localhost:8080`.

**Si quieres probar el envío de emails** sin Docker, arranca MailHog con un único comando y luego la app:

```bash
docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

### Probar endpoints

```bash
# Health check (público) — debe devolver 200
curl http://localhost:8080/api/v1/auth/health
# → {"status":"UP"}

# Register — crear cuenta nueva (devuelve 201 + par de tokens)
curl -X POST http://localhost:8080/api/v1/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","password":"S3cret!pwd","firstName":"Alice","lastName":"Doe"}'
# → 201 Created
# → {"accessToken":"eyJ...","refreshToken":"...","user":{"id":1,"email":"alice@example.com",...}}

# Login — autenticar (devuelve 200 + par de tokens)
curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"alice@example.com","password":"S3cret!pwd"}'
# → 200 OK
# → {"accessToken":"eyJ...","refreshToken":"...","user":{...}}

# Refresh — rotar refresh token (el viejo se invalida, se emite uno nuevo)
curl -X POST http://localhost:8080/api/v1/auth/refresh \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"<pegar-refresh-token-del-login>"}'
# → 200 OK + nuevos tokens (rotacion atomica)

# Logout — revocar refresh token (idempotente: no falla si ya estaba revocado)
curl -X POST http://localhost:8080/api/v1/auth/logout \
     -H "Content-Type: application/json" \
     -d '{"refreshToken":"<refresh-token>"}'
# → 204 No Content

# Endpoint protegido sin token — debe dar 401
curl -i http://localhost:8080/api/v1/users/me
# → HTTP/1.1 401 Unauthorized
# → WWW-Authenticate: Bearer realm="auth-service"

# Endpoint protegido con token inválido — debe dar 401
curl -i -H "Authorization: Bearer not.a.real.jwt" \
     http://localhost:8080/api/v1/users/me
# → HTTP/1.1 401 Unauthorized
```

#### 🧪 Smoke test end-to-end (con Docker)

Flujo completo que valida los 5 componentes principales del servicio (PostgreSQL, Flyway, BCrypt, JWT, JavaMailSender) en menos de 1 minuto. Requiere tener `docker compose up` corriendo.

**Paso 1: registrar usuario nuevo**

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"correcto-caballo-bateria-grapa-9421","firstName":"Alice","lastName":"Doe"}'
# → HTTP/1.1 201 Created
# → {"accessToken":"eyJ...","refreshToken":"...","user":{"id":1,...,"roles":["ROLE_USER"]}}
```

**Paso 2: comprobar que Flyway aplicó las migraciones**

```bash
docker compose logs auth-service | grep -iE 'flyway|migrat' | head -10
# → "Migrating schema "public" to version "1 - init schema""
# → "Migrating schema "public" to version "2 - add version column""
# → "Successfully applied 2 migrations to schema "public""
```

**Paso 3: listar las tablas creadas en PostgreSQL**

```bash
docker compose exec postgres psql -U authuser -d authdb -c '\dt'
# → 6 tablas: flyway_schema_history, password_reset_tokens, refresh_tokens,
#             roles, user_roles, users
```

**Paso 4: iniciar el flujo de password reset**

```bash
# 4a) pedir el email de reset (devuelve 202 exista o no el email)
curl -i -X POST http://localhost:8080/api/v1/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'
# → HTTP/1.1 202 Accepted

# 4b) abrir MailHog en http://localhost:8025 y copiar el token del link
#     (formato: http://localhost:5173/reset-password?token=<TOKEN>)

# 4c) canjear el token y actualizar la password
curl -i -X POST http://localhost:8080/api/v1/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"token":"<TOKEN_DEL_EMAIL>","newPassword":"MiNuevaPasswordSegura-2026"}'
# → HTTP/1.1 204 No Content
```

**Paso 5: login con la nueva password**

```bash
curl -i -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"MiNuevaPasswordSegura-2026"}'
# → HTTP/1.1 200 OK
# → nuevos accessToken + refreshToken (la password anterior ya no funciona)
```

**Resultado esperado:** los 5 pasos devuelven los códigos HTTP indicados. Si alguno falla, los logs de la app están en `docker compose logs auth-service` y los emails enviados en http://localhost:8025.

---

## ✅ Tests

```bash
# Todos los tests
mvn -B test

# Solo tests de seguridad
mvn -B test -Dtest='Jwt*,SecurityConfigTest'

# Solo tests de repositorios
mvn -B test -Dtest='*RepositoryTest'

# Tests con detalle verbose
mvn -B test -X
```

**Cobertura actual:**

- **Tests:** 100 / 100 passing · 0 flaky (15 clases: 79 `@Test` + 3 `@ParameterizedTest` expanden los 21 casos restantes)
- **Line coverage (JaCoCo):** 95% — 362 de 382 lineas cubiertas por los tests
- **Branch coverage:** 89% — 136 de 152 ramas cubiertas
- **Class coverage:** 100% — los 40 classes del main tienen al menos un test que invoca su codigo (medicion a nivel de "clase tocada", NO garantiza que todas las lineas o ramas esten ejercitadas; para eso mirar line/branch coverage arriba)
- **Gap conocido:** 5% de lineas sin cubrir = ramas defensivas (validacion de entrada redundante, paths de excepcion con mime types no soportados). Tests cubren el happy path + los errores mas probables; el resto es codigo de defensa en profundidad esperado en cualquier servicio de auth.
- **Reporte completo:** `target/site/jacoco/index.html` tras `mvn verify` (no se ejecuta en `mvn test` por diseno: separa ejecucion rapida de analisis profundo)

**Perfiles de test:**
- `@DataJpaTest` — tests de repositorios con H2 aislada (UUID por test)
- `@SpringBootTest` — tests de integración con MockMvc
- Pure unit tests (`JwtTokenProviderTest`) — sin Spring context, super rápidos

---

## 🚀 CI / Deployment

**CI (GitHub Actions):** `.github/workflows/ci.yml`
- Trigger: push y pull_request a `main`
- Job: `ubuntu-latest` + Temurin JDK 21
- Comando: `mvn -B verify` (compile + test + package)
- Cache automático de `~/.m2/repository` via `actions/setup-java@v4`
- Timeout: 15 minutos · `concurrency` cancela runs redundantes

**Perfiles de Spring Boot:**

| Perfil | DB | Mail | Cuándo usarlo |
|---|---|---|---|
| `dev` | H2 in-memory | MailHog (Docker) | Desarrollo local |
| `test` | H2 isolated (UUID) | desactivado | Tests automatizados |
| `prod` | PostgreSQL | SMTP real (env vars) | Despliegue |

**Variables de entorno (producción):**

```bash
# JWT (mínimo 32 bytes / 256 bits para HS256)
JWT_SECRET=$(openssl rand -base64 48)

# CORS (CSV)
APP_CORS_ORIGINS=https://mi-frontend.com

# Database (cuando se conecte a PostgreSQL)
SPRING_DATASOURCE_URL=jdbc:postgresql://...
SPRING_DATASOURCE_USERNAME=...
SPRING_DATASOURCE_PASSWORD=...

# Mail (para password-reset)
SPRING_MAIL_HOST=smtp.example.com
SPRING_MAIL_PORT=587
SPRING_MAIL_USERNAME=...
SPRING_MAIL_PASSWORD=...

# Política de contraseña (Nivel NIST SP 800-63B, default 3 = "safely unguessable")
# Rango válido: 0 (muy débil) a 4 (muy fuerte). Cambiar sin redeploy.
APP_SECURITY_PASSWORD_POLICY_MIN_ZXCVBN_SCORE=3
```

---

## 📂 Estructura del proyecto

```
auth-service/
├── .github/
│   └── workflows/
│       └── ci.yml                       # GitHub Actions CI
├── src/
│   ├── main/
│   │   ├── java/dev/albertoarenaldev/authservice/
│   │   │   ├── AuthServiceApplication.java
│   │   │   ├── config/                 # Spring @Configuration
│   │   │   │   ├── DataSeeder.java     # Seeder idempotente de roles
│   │   │   │   ├── PasswordEncoderConfig.java
│   │   │   │   └── SecurityConfig.java
│   │   │   ├── modelo/                 # JPA entities
│   │   │   │   ├── User.java
│   │   │   │   ├── Role.java
│   │   │   │   ├── RefreshToken.java
│   │   │   │   └── PasswordResetToken.java
│   │   │   ├── repository/             # Spring Data JPA
│   │   │   │   ├── UserRepository.java
│   │   │   │   ├── RoleRepository.java
│   │   │   │   ├── RefreshTokenRepository.java
│   │   │   │   └── PasswordResetTokenRepository.java
│   │   │   ├── security/               # JWT infrastructure
│   │   │   │   ├── JwtProperties.java
│   │   │   │   ├── JwtTokenProvider.java
│   │   │   │   ├── JwtAuthenticationFilter.java
│   │   │   │   └── JwtAuthenticationEntryPoint.java
│   │   │   └── web/                    # REST controllers
│   │   │       └── AuthController.java
│   │   └── resources/
│   │       ├── application.properties          # Config base
│   │       ├── application-dev.properties      # Perfil dev
│   │       ├── application-test.properties    # Perfil test
│   │       └── application-prod.properties     # Perfil prod
│   └── test/
│       └── java/dev/albertoarenaldev/authservice/
│           ├── AuthServiceApplicationTests.java
│           ├── config/
│           │   └── DataSeederTest.java
│           ├── repository/
│           │   ├── UserRepositoryTest.java
│           │   ├── RefreshTokenRepositoryTest.java
│           │   └── PasswordResetTokenRepositoryTest.java
│           └── security/
│               ├── JwtPropertiesTest.java
│               ├── JwtTokenProviderTest.java
│               └── SecurityConfigTest.java
├── .gitignore
├── LICENSE                              # MIT
├── pom.xml
└── README.md                            # ← estás aquí
```

**Convenciones del proyecto:**

- Sin Lombok (consistencia con proyecto hermano). Getters/setters explícitos.
- `snake_case` en columnas con `@Column(name=...)`. `camelCase` en campos Java.
- Timestamps via `@PrePersist`/`@PreUpdate` con `Instant`.
- Javadoc en clases de seguridad y entidades (el "por qué", no el "qué").
- Tests con nombres descriptivos que explican el escenario.
- Commits en castellano, mensajes profesionales, sin referencias a herramientas de review.

---

## 🗺️ Roadmap

| Fase | Estado | Descripción |
|---|---|---|
| **Fase 1** | ✅ | Setup del proyecto + perfiles + dependencias |
| **Fase 2** | ✅ | Modelo de datos + repositorios + tests |
| **Fase 3** | ✅ | Infraestructura JWT (filter, entry point, BCrypt, security config) |
| **Fase 4** | ✅ | Endpoints de auth (register, login, refresh, logout) |
| **Fase 5** | ✅ | Password reset flow + NIST SP 800-63B password policy + optimistic locking en tokens de un solo uso |
| **Fase 6** | ⏳ | User profile endpoints + change password |
| **Fase 7** | ⏳ | Rate limiting (login attempts, password reset) |
| **Fase 8** | ⏳ | Audit log (login events, password changes) |
| **Fase 9** | ⏳ | OAuth2 / OIDC (login con Google, GitHub) |

---

## 🤝 Contribuir

1. **Fork** el repo y clona tu fork
2. Crea una rama desde `main`:
   ```bash
   git checkout -b feat/mi-feature
   ```
3. Haz commits pequeños y descriptivos (mensajes en castellano)
4. Asegúrate de que `mvn -B verify` pasa en local
5. Push y abre un Pull Request a `main`
6. CI debe pasar antes de mergear

**Convenciones de commit:**

- Mensajes en castellano, formato `tipo(scope): descripción`
- Tipos: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `chore`
- Tests obligatorios para código nuevo
- Javadoc en clases de seguridad y entidades
- Sin Lombok

**Reportar bugs:** abre un issue con:

- Pasos para reproducir
- Comportamiento esperado vs real
- Versión (commit SHA)
- Logs relevantes

---

## 📄 Licencia

MIT — ver [LICENSE](LICENSE) para el texto completo.

Copyright (c) 2025 Alberto Arenaldev
