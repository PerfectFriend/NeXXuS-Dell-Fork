# GUÍA DE USUARIO — NeXXuS Sovereign Protocol (v0.229.0)

> **Versiones de idioma:** [English](USER_GUIDE.en.md) | [Español](USER_GUIDE.es.md) | [Русский](USER_GUIDE.ru.md)

Bienvenido a la Guía Oficial de Usuario de **NeXXuS Sovereign Protocol** — una red de almacenamiento distribuido P2P y mensajería cifrada de extremo a extremo, que opera de forma nativa sobre Tor Onion v3 con protección criptográfica híbrida Post-Cuántica.

---

## 📑 Tabla de Contenidos
1. [Arquitectura y Principios Fundamentales](#1-arquitectura-y-principios-fundamentales)
2. [Inicio Rápido e Instalación](#2-inicio-rápido-e-instalación)
   - [Linux / Ubuntu / Debian](#21-linux--ubuntu--debian)
   - [Windows 10 / 11](#22-windows-10--11)
   - [Android (Termux y Móvil)](#23-android)
3. [Configuración (`node.conf`) y Variables de Entorno](#3-configuración-nodeconf-y-variables-de-entorno)
4. [Identidad Criptográfica Soberana y Seed Vault](#4-identidad-criptográfica-soberana-y-seed-vault)
5. [Sovereign Drive: Sincronización Automática de Carpetas](#5-sovereign-drive-sincronización-automática-de-carpetas)
6. [Mensajería E2EE SMP y Contactos QR (ContactLink)](#6-mensajería-e2ee-smp-y-contactos-qr-contactlink)
7. [Recuperación ante Desastres desde la Red Mesh (PROD-RESTORE-01)](#7-recuperación-ante-desastres-desde-la-red-mesh-prod-restore-01)
8. [Modo Proveedor de Almacenamiento (CLI & UI)](#8-modo-proveedor-de-almacenamiento-cli--ui)
9. [Protección Post-Cuántica (PQC) y ZK-SNARK PoR](#9-protección-post-cuántica-pqc-y-zk-snark-por)
10. [Referencia Completa de Comandos CLI (`nexxusd`)](#10-referencia-completa-de-comandos-cli-nexxusd)
11. [Monitor de Escritorio (Aplicación Gráfica Tauri)](#11-monitor-de-escritorio-aplicación-gráfica-tauri)
12. [Seguridad, Auditoría y Resolución de Problemas](#12-seguridad-auditoría-y-resolución-de-problemas)

---

## 1. Arquitectura y Principios Fundamentales

NeXXuS opera sin servidores centrales, coordinadores ni intermediarios en la nube:
- **Fragmentación Fija a 16 KiB**: Cada archivo se divide en bloques exactos de 16.384 bytes.
- **Codificación Reed-Solomon RS(4+2)**: Cada bloque se expande a 6 fragmentos (4 de datos + 2 de paridad). La información es completamente recuperable incluso si 2 de cada 6 nodos fallan simultáneamente.
- **Cifrado XChaCha20-Poly1305 AEAD**: Cada fragmento se sella con claves únicas. Los nodos que almacenan los datos solo ven texto cifrado pseudoaleatorio y no pueden inspeccionar el contenido.
- **Transporte Nativo Tor Onion v3**: Las conexiones P2P se enrutan mediante servicios ocultos `.onion`, garantizando anonimato total, ocultando direcciones IP físicas y atravesando CGNAT y cortafuegos sin necesidad de abrir puertos.
- **Proof-of-Retrievability (PoR)**: Verificación criptográfica periódica (< 3 segundos) que demuestra la posesión real de los datos sin transferir los archivos por la red.

---

## 2. Inicio Rápido e Instalación

### 2.1. Linux / Ubuntu / Debian

**Instalación en una sola línea:**
```bash
curl -fsSL https://raw.githubusercontent.com/PerfectFriend/NeXXus-Node/main/install.sh | bash
```

El script automatiza todo el proceso:
1. Comprueba requisitos del sistema (CPU, RAM, almacenamiento).
2. Instala el binario `nexxusd` en `/usr/local/bin/nexxusd`.
3. Prepara el directorio de trabajo `~/.nexxus`.
4. Genera una identidad BIP-39 y una dirección Tor Onion v3.
5. Habilita e inicia el servicio systemd `nexxus-node.service`.

**Ejecución manual:**
```bash
nexxusd serve
```

### 2.2. Windows 10 / 11

1. Descargue el paquete `nexxus-node_latest_windows_x64.zip` desde las publicaciones del proyecto.
2. Descomprímalo en una carpeta local (ejemplo: `C:\NeXXuS`).
3. Abra PowerShell como Administrador:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope Process
   .\scripts\windows\install-service.ps1
   ```
4. El nodo se registrará como servicio de Windows `NeXXuSNode` con inicio automático.

### 2.3. Android

**Vía Termux (servidor 24/7 de bajo consumo):**
```bash
curl -fsSL https://raw.githubusercontent.com/PerfectFriend/NeXXus-Node/main/scripts/install-android-termux.sh | bash
```
Activa `termux-wake-lock` para evitar la suspensión del procesador con la pantalla apagada y configura el reinicio automático mediante `Termux:Boot`.

---

## 3. Configuración (`node.conf`) y Variables de Entorno

Tanto el daemon como la interfaz gráfica leen la configuración común de `~/.nexxus/node.conf`.

### Parámetros en `node.conf`:
```ini
listen=127.0.0.1:4001       # Dirección P2P de escucha
api=127.0.0.1:4010          # Puerto local WebSocket JSON-RPC
tor=1                       # Soporte Tor Onion v3 (0 o 1)
threshold=3                 # Quórum de auditores por época
epoch_secs=86400            # Duración de la época diaria (en segundos)
auto_backup_hours=24        # Intervalo de copias de seguridad
auto_backup_keep=5          # Rotación de copias almacenadas
por_enabled=1               # Activar auditorías periódicas PoR
log_path=~/.nexxus/nexxusd.log
```

### Variables de Entorno:
| Variable | Por Defecto | Descripción |
|---|---|---|
| `NEXXUS_LISTEN` | `127.0.0.1:4001` | Dirección de escucha de la red P2P |
| `NEXXUS_API_LISTEN` | `127.0.0.1:4010` | Dirección del API local (protegido por token) |
| `NEXXUS_DATA_DIR` | `~/.nexxus` | Directorio de base de datos `store.redb` y claves |
| `NEXXUS_TOR` | `0` (o `1`) | Habilita enrutamiento por Tor Onion v3 |
| `NEXXUS_API_ONION` | `0` | Publica un endpoint Onion para acceso remoto al API |
| `NEXXUS_MAX_STORE_BYTES` | `0` (sin límite) | Límite máximo de disco en bytes |
| `NEXXUS_SYNC_INTERVAL_SECS`| `300` | Frecuencia de escaneo en Sovereign Drive |

---

## 4. Identidad Criptográfica Soberana y Seed Vault

NeXXuS utiliza el estándar BIP-39 (12 palabras) para la derivación de claves:
- **Node ID**: Hash SHA-256 de la clave pública Ed25519 del nodo.
- **Dirección Onion v3**: Derivada determinísticamente de la clave Ed25519 ($56\text{ caracteres base32} + \text{.onion}$).
- **Seed Vault**: Bóveda cifrada con AES-256-GCM y 600.000 iteraciones de PBKDF2. Las palabras mnemónicas en texto plano nunca se guardan en el disco.
- **PIN de Coacción (Duress-PIN)**: Si se introduce un PIN alternativo forzado, el nodo desbloquea un perfil señuelo vacío sin revelar la existencia del almacenamiento real.

---

## 5. Sovereign Drive: Sincronización Automática de Carpetas

La carpeta `~/.nexxus/drive` actúa como su disco virtual cifrado y sincronizado:
1. Coloque archivos o carpetas en `~/.nexxus/drive`.
2. El demonio detecta automáticamente los cambios, fragmenta en 16 KiB, aplica RS(4+2) y distribuye los bloques cifrados por el enjambre.
3. El índice de archivos se gestiona en la base de datos CAS local.

**Comandos CLI:**
```bash
nexxusd sync                      # Sincronización manual de la carpeta por defecto
nexxusd sync /ruta/a/mi/carpeta   # Sincronización de un directorio personalizado
nexxusd sync status               # Muestra número de archivos sincronizados y bytes
```

---

## 6. Mensajería E2EE SMP y Contactos QR (ContactLink)

El Simple Messaging Protocol (SMP) proporciona mensajería cifrada de extremo a extremo sin intermediarios centrales:

### Estándar ContactLink (Especificación §7):
Los contactos se comparten mediante un URI estándar:
```text
nexxus://contact?addr=<NodeID_Hex64>&onion=<Direccion_Tor_v3>&name=<Alias>&fp=<Huella_Clave>
```

- En el Monitor de Escritorio: haga clic en **«📷 Mi contacto QR»** para presentar su código.
- Para agregar a otro usuario, pegue su URI o escanee el código con la cámara.
- Todos los mensajes están cifrados mediante X25519-ChaCha20-Poly1305 con Secreto Perfecto hacia Adelante (PFS).

---

## 7. Recuperación ante Desastres desde la Red Mesh (PROD-RESTORE-01)

En caso de fallo total o pérdida física del hardware:
1. Instale `nexxusd` en un equipo nuevo.
2. Inicialice el nodo con su frase mnemónica:
   ```bash
   nexxusd init --mnemonic="sus doce palabras secretas de recuperacion BIP-39"
   ```
3. Ejecute la reconstrucción remota desde la red:
   ```bash
   nexxusd restore --from-mesh
   ```
4. El nodo se conectará a los pares mediante Onion v3, localizará los fragmentos RS(4+2) de su cuenta, verificará su integridad y reconstruirá su archivo completo.

---

## 8. Modo Proveedor de Almacenamiento (CLI & UI)

Cualquier operador puede alquilar espacio de almacenamiento libre en disco a otros miembros de la red:

### Comandos del Proveedor:
```bash
# Fijar un contenido por precio en nano-TON y duración en épocas
nexxusd provider pin 0123456789abcdef... --price 1000 --duration 60

# Ver el estado de capacidad del proveedor y acuerdos activos
nexxusd provider status

# Listar todos los acuerdos de almacenamiento activos
nexxusd provider list
```

En la aplicación `nexxus-desktop`, el panel **«🖥️ Proveedor de Alojamiento»** permite supervisar ingresos, espacio ocupado y contratos con un solo clic.

---

## 9. Protección Post-Cuántica (PQC) y ZK-SNARK PoR

- **FIPS 203 ML-KEM-768 ⊕ X25519 (Escudo Híbrido)**: La negociación de claves combina el protocolo clásico X25519 con el algoritmo basado en retículos Kyber-768 mediante HKDF-SHA256, eliminando riesgos ante futuros ordenadores cuánticos («Cosechar ahora, descifrar después»).
- **Succinct ZK-SNARK PoR**: Pruebas compactas de 384 bytes de conocimiento cero que verifican la custodia de terabytes de información en menos de 5 milisegundos sin descargar bloques.

---

## 10. Referencia Completa de Comandos CLI (`nexxusd`)

| Comando | Descripción | Ejemplo |
|---|---|---|
| `nexxusd serve [store]` | Inicia el demonio de almacenamiento P2P | `nexxusd serve` |
| `nexxusd init [--mnemonic]`| Genera identidad o importa frase semilla | `nexxusd init` |
| `nexxusd id` | Muestra el Node ID y la dirección Onion v3 | `nexxusd id` |
| `nexxusd status` | Estado del almacenamiento, asignación y salud | `nexxusd status` |
| `nexxusd peers` | Lista de pares P2P conectados y latencia RTT | `nexxusd peers` |
| `nexxusd peer add <IP:PORT>`| Conectar manualmente a un par | `nexxusd peer add 10.0.0.1:4001` |
| `nexxusd upload <file>` | Fragmenta (16K), RS(4+2), cifra y almacena | `nexxusd upload archivo.zip` |
| `nexxusd download <root> <out>`| Descarga y reconstruye por Merkle Root | `nexxusd download <root> out.bin` |
| `nexxusd sync [path]` | Sincroniza la carpeta Sovereign Drive | `nexxusd sync` |
| `nexxusd provider pin <root>` | Fija un acuerdo como proveedor de hosting | `nexxusd provider pin <root> --price 500` |
| `nexxusd provider status` | Consulta capacidad y acuerdos del proveedor | `nexxusd provider status` |
| `nexxusd provider list` | Lista los acuerdos de hosting registrados | `nexxusd provider list` |
| `nexxusd test-por` | Ejecuta benchmark local de prueba PoR (< 3s) | `nexxusd test-por` |
| `nexxusd doctor` | Diagnóstico de integridad de la base de datos | `nexxusd doctor` |
| `nexxusd backup` | Crea una copia de seguridad atómica cifrada | `nexxusd backup` |
| `nexxusd restore` | Restaura la base de datos desde una copia | `nexxusd restore candidate.redb` |
| `nexxusd update [--check]` | Actualizador seguro con verificación criptográfica | `nexxusd update` |

---

## 11. Monitor de Escritorio (Aplicación Gráfica Tauri)

La aplicación oficial `nexxus-desktop` ofrece un panel de control intuitivo:
- **Resumen**: Estado del servicio, tiempo de actividad, conectividad Tor y alertas de Telegram.
- **Almacenamiento**: Explorador de fragmentos, estado de Sovereign Drive, panel de proveedor de hosting.
- **Red & Pares**: Tabla de enrutamiento DHT Kademlia, ping en tiempo real a los nodos.
- **Mensajería SMP**: Buzón de entrada cifrado, escáner y generador de códigos QR.
- **Seguridad**: Gestión de respaldos, configuración de PIN de Coacción y rotación de claves.

---

## 12. Seguridad, Auditoría y Resolución de Problemas

- **Verificación de diagnóstico**:
  ```bash
  nexxusd doctor
  ```
- **Monitoreo de registros en tiempo real**:
  ```bash
  nexxusd logs -n 100
  ```
- **Divulgación de vulnerabilidades**: Consulte la política de reporte responsable en `SECURITY.md`.
