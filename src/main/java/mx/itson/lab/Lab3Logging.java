package mx.itson.lab;

import org.slf4j.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/lab3")
public class Lab3Logging {
    private static final Logger log = LoggerFactory.getLogger(Lab3Logging.class);
    private final UsuarioRepository repo;
    private final BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
    public Lab3Logging(UsuarioRepository repo) { this.repo = repo; }

    // ❌ VULNERABLE: registra la contraseña y la entrada del usuario sin sanear
    @PostMapping("/vuln/login")
    public String vuln(@RequestParam String email, @RequestParam String password) {
        log.info("Intento de login email={} password={}", email, password);
        boolean ok = repo.findByEmail(email).filter(u -> enc.matches(password, u.passwordHash)).isPresent();
        log.info("Resultado login {} para {}", ok ? "EXITOSO" : "FALLIDO", email);
        return ok ? "OK" : "Credenciales inválidas";
    }

    // ✅ MITIGADO: sin secretos, entrada saneada, correo enmascarado, formato estructurado
    @PostMapping("/safe/login")
    public String safe(@RequestParam String email, @RequestParam String password) {
        boolean ok = repo.findByEmail(email).filter(u -> enc.matches(password, u.passwordHash)).isPresent();
        String e = enmascarar(limpiar(email));
        if (ok) log.info("evento=LOGIN resultado=EXITOSO email={}", e);
        else    log.warn("evento=LOGIN resultado=FALLIDO email={}", e);
        return ok ? "OK" : "Credenciales inválidas";
    }

    static String limpiar(String s) {
        String t = s.replaceAll("[\\r\\n\\t]", "_");        // neutraliza CR/LF (CWE-117)
        return t.length() > 60 ? t.substring(0, 60) : t;     // limita longitud
    }

    static String enmascarar(String correo) {
        return correo.replaceAll("(?<=.{2}).(?=[^@]*@)", "*"); // an***@itson.mx
    }
}
