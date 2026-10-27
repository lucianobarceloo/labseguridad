package mx.itson.lab;

import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/lab1")
public class Lab1Datos {
    public record UsuarioDto(Long id, String nombre, String email, String tarjeta, String rol) {}

    private final UsuarioRepository repo;
    public Lab1Datos(UsuarioRepository repo) { this.repo = repo; }

    // ❌ VULNERABLE: expone la entidad completa (passwordHash, curp, tarjeta completa)
    @GetMapping("/vuln/usuarios")
    public List<Usuario> vuln() { return repo.findAll(); }

    // ✅ MITIGADO: DTO con lista blanca + enmascarado + Reto (rol)
    @GetMapping("/safe/usuarios")
    public List<UsuarioDto> safe() {
        return repo.findAll().stream()
                .map(u -> new UsuarioDto(u.id, u.nombre, u.email,
                        "**** **** **** " + u.tarjeta.substring(u.tarjeta.length() - 4),
                        u.rol))
                .toList();
    }
}
