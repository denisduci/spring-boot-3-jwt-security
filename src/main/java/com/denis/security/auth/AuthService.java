package com.denis.security.auth;

import com.denis.security.config.JwtService;
import com.denis.security.user.User;
import com.denis.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Service class responsible for user authentication and registration.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Registers a new user with the provided registration request.
     *
     * @param request Registration request containing user details.
     * @return Authentication response containing JWT access token.
     * @throws IllegalArgumentException if the username already exists.
     */
    public AuthResponse register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new IllegalArgumentException("Username already exists %s".formatted(request.getUsername()));
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        userRepository.save(user);

        Authentication authentication = authenticateUser(request.getUsername(), request.getPassword());

        String token = jwtService.createToken(authentication);

        return AuthResponse.builder()
                .accessToken(token)
                .build();
    }

    /**
     * Authenticates a user with the provided authentication request.
     *
     * @param request Authentication request containing username and password.
     * @return Authentication response containing JWT access token.
     */
    public AuthResponse authenticate(AuthRequest request) {

        Authentication authentication = authenticateUser(request.getUsername(), request.getPassword());

        String token = jwtService.createToken(authentication);

        return AuthResponse.builder()
                .accessToken(token)
                .build();
    }

    /**
     * Authenticates a user with the provided username and password.
     */
    private Authentication authenticateUser(String username, String password) {
        Authentication authentication =
                authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return authentication;
    }
}
