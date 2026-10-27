package mx.itson.lab;

import jakarta.persistence.*;

@Entity
public class Usuario {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) public Long id;
    public String nombre, email, passwordHash, curp, tarjeta, rol;

    public static Usuario of(String n, String e, String h, String c, String t, String r) {
        Usuario u = new Usuario();
        u.nombre = n; u.email = e; u.passwordHash = h; u.curp = c; u.tarjeta = t; u.rol = r;
        return u;
    }
}
