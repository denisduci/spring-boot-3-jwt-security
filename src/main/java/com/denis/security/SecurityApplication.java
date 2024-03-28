package com.denis.security;

import com.denis.security.auth.AuthService;
import com.denis.security.auth.RegisterRequest;
import com.denis.security.user.Role;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
@Log4j2
public class SecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    public CommandLineRunner commandLineRunner(AuthService service) {
        return args -> {
            var admin = RegisterRequest.builder()
                    .firstName("Admin")
                    .lastName("Admin")
                    .username("admin123")
                    .password("password")
                    .role(Role.ADMIN)
                    .build();
            log.info("Admin token: " + service.register(admin).getAccessToken());

            var manager = RegisterRequest.builder()
                    .firstName("Manager")
                    .lastName("Manager")
                    .username("manage123")
                    .password("password")
                    .role(Role.MANAGER)
                    .build();
            log.info("Manager token: " + service.register(manager).getAccessToken());

        };
    }
}
