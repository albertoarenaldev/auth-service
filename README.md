# auth-service

[![CI](https://github.com/albertoarenaldev/auth-service/actions/workflows/ci.yml/badge.svg)](https://github.com/albertoarenaldev/auth-service/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.5-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Auth Service — stateless JWT authentication built with Spring Boot 3 + Spring Security 6.
> Designed as a portfolio project showcasing clean architecture, testable security, and 12-factor config.

---

## 📑 Tabla de contenidos

- [Estado del proyecto](#-estado-del-proyecto)
- [Stack](#-stack)
- [Arquitectura](#-arquitectura)
- [Endpoints](#-endpoints)
- [Desarrollo local](#-desarrollo-local)
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
| **Fase 4** — Endpoints | ⏳ | register, login, refresh (placeholder actual: `GET /api/v1/auth/health`) |
| **Fase 5** — Password reset | ⏳ | Flujo completo con email token + endpoint público |
| **Fase 6** — User profile | ⏳ | `GET/PUT /api/v1/users/me`, change password |

**Tests:** 29/29 verde · **Java:** 21 · **Spring Boot:** 3.5.5

---

## 🧰 Stack

| Capa | Tecnología |
|---|---|
| Lenguaje | Java 21 (Temurin) |
| Framework | Spring Boot 3.5.5 |
| Seguridad | Spring Security 6.x, JJWT 0.12.5 (HS256), BCrypt strength 12 |
| Persistencia | JPA + Hibernate, H2 (dev/test), PostgreSQL (prod) |
| Build | Maven 3.9+ |
| Tests | JUnit 5, AssertJ, MockMvc, @DataJpaTest |
| Mail | Spring Mail (JavaMailSender) + MailHog (dev) |
| CI | GitHub Actions (Ubuntu + Temurin JDK 21) |
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
| `GET` | `/actuator/health` | público | Health check agregado (DB, disk, mail) |
| `GET` | `/actuator/info` | 🔒 autenticado | Metadata del build (protegido para evitar info leak) |

### Planificados (V1.1)

| Método | Path | Auth | Descripción |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | público | Crear cuenta: `{email, password, firstName, lastName}` |
| `POST` | `/api/v1/auth/login` | público | Login: `{email, password}` → `{accessToken, refreshToken, user}` |
| `POST` | `/api/v1/auth/refresh` | público | Renovar access token con refresh token válido |
| `POST` | `/api/v1/auth/logout` | 🔒 autenticado | Revocar refresh token (logout) |
| `POST` | `/api/v1/auth/password/reset/request` | público | Solicitar email de reset |
| `POST` | `/api/v1/auth/password/reset/confirm` | público | Confirmar reset con token |
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

### Requisitos

- Java 21 (Temurin recomendado)
- Maven 3.9+
- Docker (opcional, para MailHog)

### Setup

```bash
git clone https://github.com/albertoarenaldev/auth-service.git
cd auth-service

# Sin Docker (usa SMTP mock o desactiva MailHealth)
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Con MailHog (para probar envío de emails reales)
docker run -d --name mailhog -p 1025:1025 -p 8025:8025 mailhog/mailhog
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

La app arranca en `http://localhost:8080`.

### Probar endpoints

```bash
# Health check (público) — debe devolver 200
curl http://localhost:8080/api/v1/auth/health
# → {"status":"UP"}

# Endpoint protegido sin token — debe dar 401
curl -i http://localhost:8080/api/v1/users/me
# → HTTP/1.1 401 Unauthorized
# → WWW-Authenticate: Bearer realm="auth-service"

# Endpoint protegido con token inválido — debe dar 401
curl -i -H "Authorization: Bearer not.a.real.jwt" \
     http://localhost:8080/api/v1/users/me
# → HTTP/1.1 401 Unauthorized
```

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

**Cobertura actual:** 29 tests · 100% passing · 0 flaky

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
| **Fase 4** | ⏳ | Endpoints de auth (register, login, refresh, logout) |
| **Fase 5** | ⏳ | Password reset flow (request + confirm con email) |
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
