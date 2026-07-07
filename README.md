# auth-service

<!--
  IMPORTANTE: Reemplaza <your-github-username>/<your-repo-name> por tu
  URL real de GitHub despues de hacer `git push -u origin main`. El badge
  de CI se actualizara solo en cada push/PR.
-->
[![CI](https://github.com/<your-github-username>/<your-repo-name>/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-github-username>/<your-repo-name>/actions/workflows/ci.yml)
[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.5-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Auth Service — Spring Boot 3 + Spring Security + JWT (portfolio project).

## Stack

- **Java** 21 (Temurin)
- **Spring Boot** 3.5.5
- **Spring Security** 6.x — stateless, JWT-based
- **JPA** + Hibernate — H2 (dev) / PostgreSQL (prod)
- **JJWT** 0.12.5 — access tokens (HS256)
- **BCrypt** — password hashing (strength 12)
- **JUnit 5** + **AssertJ** + **MockMvc** — tests

## Perfiles

| Perfil | DB | Mail | Uso |
|---|---|---|---|
| `dev` | H2 in-memory | MailHog (Docker) | Desarrollo local |
| `test` | H2 isolated (UUID) | desactivado | Tests automatizados |
| `prod` | PostgreSQL | SMTP real (env vars) | Despliegue |

## Build y tests

```bash
mvn -B verify
```

29 tests (unit + integración con MockMvc) — todos en verde.

## CI

GitHub Actions corre `mvn -B verify` en cada push y PR a `main`
sobre Ubuntu + Temurin JDK 21. Workflow en `.github/workflows/ci.yml`.

## Estado del proyecto

- ✅ Modelo de datos (User, Role, RefreshToken, PasswordResetToken)
- ✅ Infraestructura de seguridad (JWT, filtros, entry point, BCrypt)
- ✅ Tests de repositorios + seguridad (29/29 verde)
- ⏳ Endpoints de auth (register, login, refresh) — pendiente
- ⏳ Password reset flow — pendiente

## Licencia

MIT
