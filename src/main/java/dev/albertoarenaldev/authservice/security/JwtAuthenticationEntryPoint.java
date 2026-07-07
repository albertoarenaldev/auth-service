package dev.albertoarenaldev.authservice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Maneja 401 (Unauthorized) devolviendo un cuerpo JSON limpio y consistente
 * en vez de la página HTML por defecto de Spring Security.
 *
 * <p>El cuerpo tiene la forma:
 * <pre>{@code
 * {
 *   "timestamp": "2025-07-07T12:34:56.789Z",
 *   "status": 401,
 *   "error": "Unauthorized",
 *   "message": "...",
 *   "path": "/api/v1/..."
 * }
 * }</pre>
 *
 * <p>Se activa cuando un endpoint protegido se accede sin autenticación
 * válida (filtro JWT no populó el SecurityContext, o el token era inválido).
 */
@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getRequestURI());

        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
