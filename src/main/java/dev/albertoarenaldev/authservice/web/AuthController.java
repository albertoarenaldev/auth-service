package dev.albertoarenaldev.authservice.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Placeholder — los endpoints de auth (register, login, refresh) se
 * montarán en Fase 4. Este health endpoint existe para:
 * <ul>
 *   <li>Verificar que Spring Security está activo y deja pasar {@code /api/v1/auth/**}</li>
 *   <li>Smoke checks en CI ({@code curl /api/v1/auth/health} devuelve 200)</li>
 *   <li>Tener un endpoint real en SecurityConfigTest</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
