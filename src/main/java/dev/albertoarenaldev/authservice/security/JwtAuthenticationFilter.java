package dev.albertoarenaldev.authservice.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Filtro que extrae el JWT del header {@code Authorization: Bearer XXX},
 * lo valida con {@link JwtTokenProvider}, y si es válido popula el
 * {@link SecurityContextHolder} con un {@link UsernamePasswordAuthenticationToken}
 * (principal=email, authorities=roles del token).
 *
 * <p>Si el token no existe, está mal formado, o es inválido, el filtro
 * deja pasar la request sin autenticar — Spring Security rechazará con
 * 401 (vía {@link JwtAuthenticationEntryPoint}) si el endpoint requiere
 * autenticación.
 *
 * <p>Optimización: usa {@link JwtTokenProvider#validateAndGetClaims(String)}
 * para parsear el token UNA SOLA VEZ por request (antes se parseaba 3 veces:
 * una en validateToken, otra en getEmailFromToken, otra en getRolesFromToken).
 *
 * <p>Se ejecuta una vez por request (OncePerRequestFilter), antes del
 * {@code UsernamePasswordAuthenticationFilter} de Spring Security.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider tokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractToken(request);

        if (StringUtils.hasText(token)) {
            // Un solo parse del token: valida Y extrae claims en la misma llamada.
            Optional<Claims> maybeClaims = tokenProvider.validateAndGetClaims(token);
            if (maybeClaims.isPresent()) {
                Claims claims = maybeClaims.get();
                String email = claims.getSubject();
                List<String> roles = extractRoles(claims);
                authenticate(request, email, roles);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    /**
     * Extrae el claim {@code roles} de los claims ya parseados. Devuelve
     * lista vacia si el claim no existe o no es una lista (defensa contra
     * tokens malformados).
     */
    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {
        Object rolesClaim = claims.get("roles");
        if (rolesClaim instanceof List<?> list) {
            return (List<String>) list;
        }
        return List.of();
    }

    private void authenticate(HttpServletRequest request, String email, List<String> roles) {
        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                email, null, authorities);
        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
