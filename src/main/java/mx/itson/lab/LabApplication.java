package mx.itson.lab;

import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class LabApplication {
    public static void main(String[] args) { SpringApplication.run(LabApplication.class, args); }

    @Bean CommandLineRunner seed(UsuarioRepository r) {
        return args -> {
            if (r.count() > 0) return;
            var enc = new BCryptPasswordEncoder();
            r.save(Usuario.of("Ana Pérez", "ana@itson.mx", enc.encode("Ana-2026"),
                    "PEXA900101MSRRNN01", "4111111111111111", "USER"));
            r.save(Usuario.of("Admin", "admin@itson.mx", enc.encode("Admin-2026"),
                    "AAAA800101HSRDMN02", "5500000000000004", "ADMIN"));
        };
    }
}
