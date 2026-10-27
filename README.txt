Laboratorio Ciberseguridad Aplicada - Proteccion de Datos y Manejo de Estado
Requisitos: JDK 17+, Maven (o NetBeans con acceso a Internet para descargar dependencias de Maven Central). Guia: GUIA.html

1) Generar dos llaves de 256 bits (hex, 64 caracteres):
   openssl rand -hex 32
   PowerShell 5.1:
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 32
$rng.GetBytes($bytes)
$hex = [System.BitConverter]::ToString($bytes) -replace '-', ''
$rng.Dispose()
$hex

   PowerShell 7+: [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))

2) Ejecutar (PowerShell):
   $env:LAB_AES_KEY="<hex1>"; $env:LAB_JWT_KEY="<hex2>"; mvn spring-boot:run
   Bash:  LAB_AES_KEY=<hex1> LAB_JWT_KEY=<hex2> mvn spring-boot:run
   NetBeans: File > Open Project > carpeta labseguridad; clic derecho > Run Maven > Goals...:
   spring-boot:run, Set Properties: spring-boot.run.jvmArguments=-DLAB_AES_KEY=<hex1> -DLAB_JWT_KEY=<hex2>

3) App en http://localhost:8080 . Usuarios: ana@itson.mx / Ana-2026 (USER), admin@itson.mx / Admin-2026 (ADMIN)
Las practicas 1-3 funcionan sin llaves. Uso exclusivo en localhost con fines educativos.
