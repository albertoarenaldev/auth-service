# =====================================================================
# Auth Service — Multi-stage Dockerfile
# =====================================================================
# Stage 1 (build): compila el jar con Maven sobre Temurin JDK 21.
# Stage 2 (runtime): ejecuta el jar sobre Temurin JRE 21 Alpine
#                    (imagen ligera ~250 MB vs ~600 MB del JDK completo).
#
# Build:    docker build -t auth-service:dev .
# Run:      docker run --rm -p 8080:8080 auth-service:dev
# Compose:  ver docker-compose.yml en la raiz del repo
# =====================================================================

# ---------------------------------------------------------------------
# Stage 1: build
# ---------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /workspace

# Cache de dependencias primero. Si pom.xml no cambia, esta capa se
# reusa en builds sucesivos y evita re-descargar ~200 MB de deps.
COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline

# Ahora el codigo fuente. Esta capa se invalida solo cuando src/ cambia.
COPY src ./src

# Empaqueta sin tests (los corre CI con `mvn verify`).
RUN mvn -B -ntp clean package -DskipTests

# ---------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Zona horaria consistente con la BD y los timestamps de JWT/tokens.
ENV TZ=UTC

# Usuario no-root (least-privilege). Alpine usa addgroup/adduser
# de busybox; -S = system group/user.
RUN addgroup -S app && adduser -S app -G app

# Copiamos el jar construido en el stage anterior. --chown fija el
# dueno al usuario no-root para que pueda leerlo.
COPY --from=build --chown=app:app /workspace/target/*.jar app.jar

# Puerto por defecto de Spring Boot (application.properties: server.port=8080)
EXPOSE 8080

# Healthcheck contra /actuator/health. wget viene incluido en busybox
# de la imagen Alpine, no requiere apk add. start-period da tiempo a
# la app para arrancar y a Flyway para aplicar las migraciones.
HEALTHCHECK --interval=30s --timeout=3s --start-period=60s --retries=3 \
  CMD wget -qO- http://localhost:8080/actuator/health 2>/dev/null | grep -q '"status":"UP"' || exit 1

# Cambiamos a usuario no-root antes de arrancar la JVM.
USER app

# Entry point. SPRING_PROFILES_ACTIVE se sobreescribe en docker-compose.yml
# (usamos `prod` + overrides de mail para apuntar a MailHog).
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
