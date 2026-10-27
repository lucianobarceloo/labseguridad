package mx.itson.lab;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

public class Lab4Cifrado {

    @Service
    public static class Crypto {
        @Value("${LAB_AES_KEY:}") private String hex;
        private final SecureRandom rnd = new SecureRandom();

        private SecretKeySpec key() {
            if (hex.length() != 64) throw new IllegalStateException("Defina LAB_AES_KEY (64 hex)");
            return new SecretKeySpec(HexFormat.of().parseHex(hex), "AES");
        }

        public String cifrar(String texto) {
            try {
                byte[] iv = new byte[12];
                rnd.nextBytes(iv);                                  // IV nuevo por registro
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, key(), new GCMParameterSpec(128, iv));
                byte[] ct = c.doFinal(texto.getBytes(StandardCharsets.UTF_8));
                byte[] out = new byte[12 + ct.length];
                System.arraycopy(iv, 0, out, 0, 12);
                System.arraycopy(ct, 0, out, 12, ct.length);        // guardamos IV || cifrado+tag
                return Base64.getEncoder().encodeToString(out);
            } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
        }

        public String descifrar(String b64) {
            try {
                byte[] in = Base64.getDecoder().decode(b64);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, in, 0, 12));
                return new String(c.doFinal(in, 12, in.length - 12), StandardCharsets.UTF_8); // valida el tag
            } catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
        }
    }

    @RestController @RequestMapping("/lab4")
    public static class Ctl {
        private final JdbcTemplate jdbc;
        private final Crypto crypto;
        public Ctl(JdbcTemplate jdbc, Crypto crypto) { this.jdbc = jdbc; this.crypto = crypto; }

        // ❌ VULNERABLE: texto plano en la BD
        @PostMapping("/vuln/notas")
        public String guardarPlano(@RequestParam String usuario, @RequestParam String contenido) {
            jdbc.update("INSERT INTO nota_plana(usuario, contenido) VALUES (?, ?)", usuario, contenido);
            return "guardada";
        }

        // ✅ MITIGADO: AES-256-GCM antes de persistir
        @PostMapping("/safe/notas")
        public String guardarCifrada(@RequestParam String usuario, @RequestParam String contenido) {
            jdbc.update("INSERT INTO nota_cifrada(usuario, contenido) VALUES (?, ?)",
                    usuario, crypto.cifrar(contenido));
            return "guardada";
        }

        @GetMapping("/safe/notas")
        public List<Map<String, String>> leerCifradas() {
            return jdbc.query("SELECT usuario, contenido FROM nota_cifrada",
                    (rs, i) -> Map.of("usuario", rs.getString(1),
                                      "contenido", crypto.descifrar(rs.getString(2))));
        }

        // Inspección directa de la base de datos (evidencia)
        @GetMapping("/db/notas")
        public Map<String, Object> consultarTablas() {
            return Map.of(
                "tabla_plana", jdbc.queryForList("SELECT id, usuario, contenido FROM nota_plana"),
                "tabla_cifrada", jdbc.queryForList("SELECT id, usuario, contenido FROM nota_cifrada")
            );
        }

        // Simulación de ataque / alteración de integridad
        @PostMapping("/db/alterar")
        public String alterarNotaCifrada() {
            jdbc.update("UPDATE nota_cifrada SET contenido = 'A' || SUBSTRING(contenido, 2)");
            return "Nota cifrada alterada en BD";
        }
    }
}
