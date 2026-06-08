# Analizador de Tráfico de Red — Capa de Transporte OSI

**UCR IF5000 — Redes y Comunicación de Datos**

Herramienta en Python que analiza archivos `.pcap` / `.pcapng` y genera un informe técnico completo sobre la Capa de Transporte OSI, con componente de Inteligencia Artificial opcional.

---

## Inicio Rápido

### 1. Instalar dependencias

Abre una terminal dentro de la carpeta del proyecto y ejecuta:

```powershell
pip install -r requirements.txt
```

### 2. Colocar tu archivo de captura

Copia tu archivo `.pcapng` dentro de la carpeta `capturas/` del proyecto:

```powershell
copy "C:\ruta\a\tu\archivo.pcapng" capturas\
```

### 3. Ejecutar el análisis

```powershell
# Solo consola (sin IA)
python main.py "capturas\Prueba 1.pcapng" --output console

# Reporte HTML
python main.py "capturas\Prueba 1.pcapng" --output html --html-output informe.html

# Consola + HTML + analisis de IA (Groq - gratuito)
python main.py "capturas\Prueba 1.pcapng" --output both --ai --provider groq --api-key gsk_XXXXXXXXXXXXXXXX --html-output informe.html
```

### 4. Abrir el reporte HTML

```powershell
start informe.html
```

---

## Obtener API Key de IA (Groq — gratuito, sin tarjeta)

1. Ve a [console.groq.com](https://console.groq.com)
2. Crea una cuenta con Google o email
3. Menu → **API Keys** → **Create API Key**
4. Copia la key que empieza con `gsk_...`
5. Usala con `--api-key gsk_...` al ejecutar el script

---

## Estructura del Proyecto

```
analizador_red/
│
├── main.py                      <- Punto de entrada
├── requirements.txt             <- Dependencias
├── README.md                    <- Este archivo
├── PREGUNTAS_PRESENTACION.md    <- Respuestas a preguntas del docente
│
├── capturas/                    <- Coloca aqui tus archivos .pcapng
│   ├── Prueba 1.pcapng
│   └── captura TCP.pcapng
│
└── modules/
    ├── ingestion.py             <- Carga el archivo de captura
    ├── tcp_analyzer.py          <- Reconstruye sesiones TCP
    ├── udp_analyzer.py          <- Cuenta flujos UDP
    ├── protocol_classifier.py   <- Identifica protocolos de aplicacion
    ├── ai_reporter.py           <- Genera informe narrativo con IA
    └── report_generator.py      <- Produce consola y HTML
```

---

## Opciones del Comando

```
python main.py <archivo> [opciones]
```

| Opcion | Valores | Por defecto | Descripcion |
|---|---|---|---|
| `--output` | `console` / `html` / `both` | `console` | Formato de salida |
| `--html-output` | nombre del archivo | `reporte.html` | Nombre del HTML generado |
| `--ai` | (flag) | desactivado | Activa el analisis narrativo con IA |
| `--provider` | `groq` / `gemini` / `anthropic` / `ollama` / `auto` | `auto` | Proveedor de IA |
| `--api-key` | string | - | API key del proveedor |

---

## Proveedores de IA

| Proveedor | Costo | Como obtener la key |
|---|---|---|
| **Groq** (recomendado) | Gratuito | [console.groq.com](https://console.groq.com) |
| **Google Gemini** | Gratuito (con cuota) | [aistudio.google.com](https://aistudio.google.com) |
| **Anthropic Claude** | Pago | [console.anthropic.com](https://console.anthropic.com) |
| **Ollama** | Gratuito local | [ollama.com](https://ollama.com) (sin internet) |

Si no tienes ninguna key, la herramienta igual genera un resumen automatico basado en reglas.

---

## Que Analiza la Herramienta

### TCP
- Cuenta sesiones TCP y reconstruye su ciclo de vida completo
- Detecta el **three-way handshake** (SYN → SYN-ACK → ACK)
- Clasifica cada sesion en uno de estos estados:

| Estado | Significado |
|---|---|
| `ESTABLECIDA` | Handshake completo, sesion activa |
| `CERRADA_FIN` | Cierre graceful — ambos lados enviaron FIN |
| `RESET` | Cierre abrupto por flag RST |
| `SYN_INCOMPLETO` | SYN enviado sin respuesta |
| `SOLO_DATOS` | Sesion ya estaba activa cuando inicio la captura |

### UDP
- Cuenta datagramas por flujo unidireccional `(ip_origen:puerto → ip_destino:puerto)`
- No hay conexion ni handshake — cada datagrama es independiente

### Protocolos de Aplicacion
- **Por puerto:** consulta tabla de 40+ puertos IANA (HTTP=80, HTTPS=443, SSH=22, DNS=53, etc.)
- **Por DPI:** inspecciona los primeros bytes del payload buscando firmas conocidas (TLS, HTTP, SSH)

---

## Conceptos Clave

**Three-Way Handshake TCP:**
```
Cliente ──SYN──────────────▶ Servidor
Cliente ◀──────SYN + ACK─── Servidor
Cliente ──ACK──────────────▶ Servidor
                              (ESTABLISHED)
```

**Cierre Graceful (FIN):**
```
Cliente ──FIN──▶ Servidor   (quiero cerrar)
Cliente ◀──ACK── Servidor
Cliente ◀──FIN── Servidor   (yo tambien cierro)
Cliente ──ACK──▶ Servidor
```

**Cierre Abrupto (RST):** un solo paquete RST termina la conexion de inmediato, sin acuerdo previo.

**Socket:** combinacion de IP + puerto que identifica un extremo de comunicacion. Ejemplo: `192.168.1.10:443`

**HTTPS sobre UDP:** HTTP/3 usa el protocolo QUIC sobre UDP puerto 443, por eso es normal ver trafico HTTPS en la seccion UDP.

---

## Requisitos del Sistema

- Python 3.8 o superior
- Windows 10/11, Linux o macOS
- Archivo `.pcap` o `.pcapng` generado con Wireshark, tcpdump u otro capturador

---

## Preguntas Frecuentes

**Sesiones con estado SOLO_DATOS — por que aparecen?**  
La captura inicio cuando esas conexiones ya estaban activas. El handshake ocurrio antes de que Wireshark comenzara a registrar.

**Por que hay muchos RST?**  
Es normal en trafico web. Los servidores y firewalls usan RST para limpiar conexiones obsoletas o rechazar accesos no autorizados.

**Por que HTTPS aparece en UDP?**  
HTTP/3 (QUIC) corre sobre UDP puerto 443. Es cada vez mas comun en trafico web moderno (Google, YouTube, etc.).

**Puedo usar mis propias capturas de Wireshark?**  
Si. Captura trafico en Wireshark, guarda como `.pcapng` y copia el archivo a la carpeta `capturas/`.

---

*UCR — IF5000 Redes y Comunicacion de Datos*
