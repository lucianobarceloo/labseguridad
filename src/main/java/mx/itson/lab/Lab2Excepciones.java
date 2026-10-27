package mx.itson.lab;

import java.util.*;
import org.slf4j.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

public class Lab2Excepciones {

    // ❌ VULNERABLE: la excepción NoSuchElementException no se maneja
    @RestController @RequestMapping("/lab2/vuln")
    public static class VulnCtl {
        private final UsuarioRepository repo;
        public VulnCtl(UsuarioRepository repo) { this.repo = repo; }

        @GetMapping("/usuario/{id}")
        public Usuario get(@PathVariable Long id) { return repo.findById(id).get(); }
    }

    // ✅ MITIGADO: el controlador lanza, el Advice responde de forma genérica
    @RestController @RequestMapping("/lab2/safe")
    public static class SafeCtl {
        private final UsuarioRepository repo;
        public SafeCtl(UsuarioRepository repo) { this.repo = repo; }

        @GetMapping("/usuario/{id}")
        public Map<String, String> get(@PathVariable Long id) {
            Usuario u = repo.findById(id).orElseThrow(NoSuchElementException::new);
            return Map.of("nombre", u.nombre);
        }

        // Endpoint para demostración de error 500 controlado con ID de correlación
        @GetMapping("/forzar-error")
        public Map<String, String> forzarError() {
            throw new IllegalStateException("fallo de prueba");
        }
    }

    @RestControllerAdvice(assignableTypes = SafeCtl.class)
    public static class Advice {
        private static final Logger log = LoggerFactory.getLogger(Advice.class);

        @ExceptionHandler(NoSuchElementException.class)
        public ResponseEntity<Map<String, String>> noEncontrado(NoSuchElementException e) {
            return ResponseEntity.status(404).body(Map.of("error", "Recurso no encontrado"));
        }

        @ExceptionHandler(MethodArgumentTypeMismatchException.class)
        public ResponseEntity<Map<String, String>> invalido(MethodArgumentTypeMismatchException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Solicitud inválida"));
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<Map<String, String>> interno(Exception e) {
            String ref = UUID.randomUUID().toString().substring(0, 8);
            log.error("ref={} error interno no controlado", ref, e);   // detalle solo en el servidor
            return ResponseEntity.status(500).body(Map.of("error", "Error interno", "ref", ref));
        }
    }
}
