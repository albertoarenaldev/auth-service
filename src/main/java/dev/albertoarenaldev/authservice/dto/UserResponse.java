package dev.albertoarenaldev.authservice.dto;

import dev.albertoarenaldev.authservice.modelo.Role;
import dev.albertoarenaldev.authservice.modelo.User;

import java.util.List;

/**
 * Representación pública de un {@link User} para devolver en responses de auth.
 *
 * <p>Nunca incluye el password hash (es información sensible que no debe
 * salir del backend). Los roles se serializan como lista de strings
 * (ej. {@code ["ROLE_USER"]}).
 */
public record UserResponse(

        Long id,
        String email,
        String firstName,
        String lastName,
        List<String> roles

) {

    /**
     * Factory para convertir de User entity a UserResponse DTO.
     * Centraliza la lógica de serialización (especialmente los roles).
     */
    public static UserResponse from(User user) {
        List<String> roleNames = user.getRoles().stream()
                .map(Role::getName)
                .toList();
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                roleNames
        );
    }
}
