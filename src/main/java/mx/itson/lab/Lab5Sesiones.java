package mx.itson.lab;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

public class Lab5Sesiones {

    static final String CLAVE_DEBIL = "changeit-changeit-changeit-12345";   // ❌ hardcodeada y adivinable

    // ❌ VULNERABLE
    @RestController @RequestMapping("/lab5/vuln")
    public static class VulnCtl {
        private final UsuarioRepository repo;
        private final BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
        public VulnCtl(UsuarioRepository repo) { this.repo = repo; }

        @PostMapping("/login")
        public ResponseEntity<?> login(@RequestParam String email, @RequestParam String password) {
            var u = repo.findByEmail(email).filter(x -> enc.matches(password, x.passwordHash));
            if (u.isEmpty()) return ResponseEntity.status(401).body("Credenciales inválidas");
            String jwt = Jwts.builder()
                    .subject(u.get().email).claim("rol", u.get().rol).claim("curp", u.get().curp) // ❌ dato personal
                    .signWith(Keys.hmacShaKeyFor(CLAVE_DEBIL.getBytes(StandardCharsets.UTF_8)))
                    .compact();                                                                   // ❌ sin exp
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, "SESSION=" + jwt)  // ❌ sin HttpOnly / Secure / SameSite
                    .body(Map.of("token", jwt));
        }

        @GetMapping("/admin")
        public ResponseEntity<String> admin(@RequestHeader(value = "Authorization", required = false) String h) {
            try {
                Claims c = Jwts.parser()
                        .verifyWith(Keys.hmacShaKeyFor(CLAVE_DEBIL.getBytes(StandardCharsets.UTF_8)))
                        .build().parseSignedClaims(h.substring(7)).getPayload();
                return "ADMIN".equals(c.get("rol")) ? ResponseEntity.ok("Panel ADMIN")
                                                    : ResponseEntity.status(403).body("Prohibido");
            } catch (Exception e) { return ResponseEntity.status(401).body("Token inválido"); }
        }
    }

    // ✅ MITIGADO
    @Component
    public static class JwtSvc {
        @Value("${LAB_JWT_KEY:}") private String hex;

        SecretKey key() {
            if (hex.length() != 64) throw new IllegalStateException("Defina LAB_JWT_KEY (64 hex)");
            return Keys.hmacShaKeyFor(HexFormat.of().parseHex(hex));
        }

        String emitir(Usuario u) {
            Instant ahora = Instant.now();
            return Jwts.builder().issuer("lab-itson").subject(String.valueOf(u.id)).claim("rol", u.rol)
                    .issuedAt(Date.from(ahora)).expiration(Date.from(ahora.plus(Duration.ofMinutes(15))))
                    .signWith(key()).compact();
        }

        Claims validar(String token) {
            return Jwts.parser().verifyWith(key()).requireIssuer("lab-itson")
                    .build().parseSignedClaims(token).getPayload();   // valida firma, exp e iss
        }
    }

    @RestController @RequestMapping("/lab5/safe")
    public static class SafeCtl {
        private final UsuarioRepository repo;
        private final JwtSvc jwt;
        private final BCryptPasswordEncoder enc = new BCryptPasswordEncoder();
        public SafeCtl(UsuarioRepository repo, JwtSvc jwt) { this.repo = repo; this.jwt = jwt; }

        @PostMapping("/login")
        public ResponseEntity<Map<String, String>> login(@RequestParam String email, @RequestParam String password) {
            var u = repo.findByEmail(email).filter(x -> enc.matches(password, x.passwordHash));
            if (u.isEmpty()) return ResponseEntity.status(401).body(Map.of("error", "Credenciales inválidas"));
            ResponseCookie ck = ResponseCookie.from("ACCESS_TOKEN", jwt.emitir(u.get()))
                    .httpOnly(true).secure(true).sameSite("Strict")
                    .path("/lab5/safe").maxAge(Duration.ofMinutes(15)).build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, ck.toString())
                    .body(Map.of("mensaje", "Sesión iniciada"));
        }

        @GetMapping("/admin")
        public ResponseEntity<String> admin(@CookieValue(name = "ACCESS_TOKEN", required = false) String t) {
            if (t == null) return ResponseEntity.status(401).body("Sin sesión");
            try {
                Claims c = jwt.validar(t);
                return "ADMIN".equals(c.get("rol", String.class)) ? ResponseEntity.ok("Panel ADMIN")
                                                                  : ResponseEntity.status(403).body("Prohibido");
            } catch (JwtException e) { return ResponseEntity.status(401).body("Sesión inválida o expirada"); }
        }

        @PostMapping("/logout")
        public ResponseEntity<String> logout() {
            ResponseCookie ck = ResponseCookie.from("ACCESS_TOKEN", "").httpOnly(true).secure(true)
                    .sameSite("Strict").path("/lab5/safe").maxAge(0).build();
            return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, ck.toString()).body("Sesión cerrada");
        }
    }
}
