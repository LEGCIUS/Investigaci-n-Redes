# Respuestas a Preguntas Guía — Presentación IF5000

**Archivo analizado:** `captura TCP.pcapng`  
**Resultados del análisis:**  
- 553 paquetes totales | 249 TCP | 271 UDP | 33 otros  
- 24 sesiones TCP | 3 handshakes completos | 12 RST | 0 FIN graceful  
- 271 datagramas UDP | 36 flujos únicos | 29 fuentes | 20 destinos  

---

## 5.1 Capa de Transporte — TCP

### ¿Cómo distingue la herramienta una sesión TCP completa de una incompleta?

La herramienta implementa una **máquina de estados TCP** en `modules/tcp_analyzer.py` que rastrea cada sesión mediante los flags del encabezado TCP.

**Sesión completa** (`ESTABLECIDA`): se requiere observar los tres pasos del *three-way handshake*:
1. Paquete con flag **SYN** (cliente → servidor)
2. Paquete con flags **SYN + ACK** (servidor → cliente)
3. Paquete con flag **ACK** (cliente → servidor)

Solo cuando se cumplen los tres pasos se marca `handshake_complete = True`.

**Sesión incompleta** (`SYN_INCOMPLETO`): se vio el SYN inicial pero nunca llegó el SYN-ACK — puede deberse a que el servidor no respondió, el puerto está cerrado o el paquete de respuesta quedó fuera del rango de captura.

**Estado `SOLO_DATOS`**: caso especial donde la captura inició con la conexión ya establecida; el handshake ocurrió antes de que Wireshark comenzara a registrar. La herramienta los clasifica aparte para no contarlos como incompletos ni como completos.

La clave de sesión es **bidireccional**: `(min(ep1, ep2), max(ep1, ep2))`, lo que permite agrupar los paquetes de ida y vuelta bajo la misma sesión.

---

### ¿Cuántas sesiones TCP se encontraron? ¿Cuántas se cerraron limpiamente (FIN) y cuántas abruptamente (RST)?

| Métrica | Valor |
|---|---|
| Sesiones TCP totales | **24** |
| Three-way handshakes completos | **3** |
| Cierres graceful (FIN-ACK) | **0** |
| Cierres abruptos (RST) | **12** |
| Solo datos (captura tardía) | **9** |

**Cierres FIN (graceful):** La secuencia de cierre ordenado requiere que *ambos* extremos envíen un FIN y reciban un ACK (`fin_count >= 2`). En esta captura no se completó ningún cierre FIN, posiblemente porque las conexiones activas no terminaron dentro del intervalo capturado.

**Cierres RST (abruptos):** El flag RST indica terminación forzada e inmediata, sin intercambio previo. Aparecen típicamente cuando una aplicación cancela la conexión, el servidor rechaza una conexión a un puerto cerrado, o un firewall/middlebox interviene.

---

### ¿Existen sesiones TCP que permanecieron en estado ESTABLISHED durante toda la captura? ¿Qué podría indicar esto?

Sí. Las **3 sesiones en estado `ESTABLECIDA`** completaron el three-way handshake y se mantuvieron activas sin recibir FIN ni RST durante todo el tiempo de captura.

Las tres corresponden a conexiones HTTPS/TLS (puerto 443) hacia el servidor `163.178.163.184` y `142.251.215.46`. La sesión de mayor volumen transfirió **172 776 bytes en 141 paquetes** durante 5.4 segundos.

**¿Qué indica esto?**
- **Conexión de larga duración (long-lived connection):** el cliente mantiene la sesión abierta para reutilizarla, lo que es normal en HTTP/1.1 con `Keep-Alive` y en HTTP/2 (multiplexación de streams sobre una sola conexión TCP).
- **Transferencia activa:** el volumen alto de bytes sugiere descarga de contenido (streaming, actualizaciones, transferencia de archivos).
- La captura simplemente terminó antes de que la sesión cerrara; no es una anomalía.

---

### ¿Cuál es el puerto de destino más frecuente en las sesiones TCP? ¿A qué servicio corresponde?

El puerto de destino más frecuente es el **443 (HTTPS/TLS)**. Todas las sesiones TCP del top 10 se dirigen a ese puerto.

| Puerto | Protocolo | Sesiones TCP |
|---|---|---|
| 443 | HTTPS / TLS | 20 sesiones |
| 443 (TLS/HTTPS) | TLS detectado por DPI | 4 sesiones |
| 6568 | Desconocido (privado) | 1 sesión |

El puerto 443 corresponde al servicio **HTTPS** (HTTP sobre TLS/SSL). La herramienta distingue entre "HTTPS" (clasificado por número de puerto) y "TLS/HTTPS" (confirmado además por **DPI**: se detectaron los bytes de saludo TLS `\x16\x03\x00–\x04` en el payload del primer paquete).

---

## 5.2 Capa de Transporte — UDP

### ¿Cuántos datagramas UDP se identificaron? ¿Cuáles son los principales pares origen-destino?

Se identificaron **271 datagramas UDP** distribuidos en **36 flujos únicos**.

A diferencia de TCP, UDP no tiene conexiones; la herramienta define un **flujo** como la 4-tupla unidireccional `(ip_origen, puerto_origen, ip_destino, puerto_destino)`.

**Top 5 flujos por volumen de datagramas:**

| Origen | Destino | Datagramas | Bytes |
|---|---|---|---|
| 142.251.215.46:443 | 10.32.239.71:55606 | 104 | 122 587 |
| 10.32.239.71:55606 | 142.251.215.46:443 | 61 | 11 378 |
| 142.251.214.227:443 | 10.32.239.71:60157 | 13 | 9 723 |
| 10.32.239.71:59905 | 160.79.104.10:443 | 11 | 7 518 |
| 160.79.104.10:443 | 10.32.239.71:59905 | 11 | 7 283 |

El flujo dominante proviene de `142.251.215.46` (infraestructura de Google) hacia el cliente en el **puerto 55606**, con 104 datagramas y 122 KB — este es tráfico **QUIC/HTTP3**, que es HTTPS corriendo sobre UDP puerto 443.

---

### ¿Cuáles puertos UDP presentan mayor frecuencia? ¿A qué protocolos o servicios corresponden?

| Puerto | Protocolo | Descripción |
|---|---|---|
| **443** | HTTPS (QUIC/HTTP3) | Tráfico web cifrado sobre UDP — Google Chrome/Chromium usa QUIC por defecto |
| **53** | DNS | Resolución de nombres de dominio (cliente → servidor DNS) |
| **5353** | mDNS | Multicast DNS — descubrimiento local de dispositivos (Bonjour/Avahi) |
| **67/68** | DHCP | Asignación de direcciones IP en la red local |

**Distribución de flujos UDP:**

| Protocolo | Flujos |
|---|---|
| DNS | 16 |
| mDNS | 10 |
| HTTPS (QUIC) | 8 |
| DHCP | 2 |

---

### ¿Se observa algún patrón de tráfico UDP que sugiera multicast o broadcast?

Sí, se identificaron **dos patrones** claramente:

**Multicast — mDNS (puerto 5353):**  
Múltiples hosts de la red envían datagramas UDP hacia la dirección `224.0.0.251`, que es la dirección multicast reservada para mDNS (RFC 6762). Participan al menos 3 hosts distintos (`10.32.236.74`, `10.32.238.64`, `10.32.238.237`). mDNS se usa para descubrir servicios locales sin necesidad de un servidor DNS central (ej: impresoras, Chromecast, dispositivos Apple).

**Broadcast — DHCP (puertos 67/68):**  
Se observan 7 datagramas entre `0.0.0.0:68` y `255.255.255.255:67`. La dirección origen `0.0.0.0` indica que el cliente aún no tiene IP asignada; la dirección destino `255.255.255.255` es el broadcast limitado de capa 3. Este patrón es el inicio del protocolo DORA (Discover → Offer → Request → Acknowledge) de DHCP.

---

## 5.3 Identificación de Aplicaciones

### ¿Qué método utiliza la herramienta para clasificar el protocolo de aplicación?

La herramienta implementa una clasificación de **dos capas** en `modules/protocol_classifier.py`:

**Capa 1 — Clasificación por puerto (Port-based):**  
Se consulta un diccionario con más de 40 puertos bien conocidos (IANA). Si el puerto origen o destino coincide, se asigna el protocolo correspondiente. Ejemplos: puerto 80 → HTTP, puerto 443 → HTTPS, puerto 22 → SSH, puerto 53 → DNS.

**Capa 2 — Inspección Profunda de Paquetes (DPI — Deep Packet Inspection):**  
Se examina el payload (carga útil) del paquete buscando **firmas de bytes** características de cada protocolo:

| Protocolo | Firma en payload |
|---|---|
| TLS/HTTPS | Bytes `\x16\x03\x00` a `\x16\x03\x04` (TLS Handshake Record) |
| HTTP | Verbos ASCII: `GET `, `POST `, `HTTP/` |
| SSH | Cadena de texto `SSH-` al inicio |
| SMTP | Comandos `EHLO`, `HELO` |

**Prioridad:** DPI tiene precedencia sobre la clasificación por puerto. Si no hay payload disponible se aplica solo el puerto. Como heurística adicional, puertos >= 49152 se clasifican como `Dinamico/Privado`.

---

### ¿Cuáles protocolos de capa de aplicación identifica la herramienta en la captura?

La herramienta identificó los siguientes protocolos en `captura TCP.pcapng`:

**Sobre TCP:**
| Protocolo | Sesiones | Método de detección |
|---|---|---|
| HTTPS | 20 | Puerto 443 |
| TLS/HTTPS | 4 | DPI (firma `\x16\x03\x0x`) |

**Sobre UDP:**
| Protocolo | Flujos | Método de detección |
|---|---|---|
| DNS | 16 | Puerto 53 |
| mDNS | 10 | Puerto 5353 + destino 224.0.0.251 |
| HTTPS (QUIC) | 8 | Puerto 443 |
| DHCP | 2 | Puertos 67/68 + broadcast |

En total se detectaron **5 protocolos de aplicación distintos**, todos relacionados con actividad web y servicios de red típicos de una estación de trabajo conectada a internet.

---

### ¿Cómo identifica tráfico cifrado (TLS/HTTPS) sin acceso al payload?

Esta es una de las preguntas más técnicas. La herramienta usa **dos estrategias complementarias**:

**1. Puerto de destino 443:**  
Por convención IANA, el puerto TCP 443 está asignado a HTTPS. Aunque el payload esté cifrado, el número de puerto es visible en el encabezado TCP en texto plano. La herramienta clasifica estas sesiones como `HTTPS`.

**2. Firma del TLS Handshake (DPI sobre los primeros bytes):**  
El saludo TLS (*ClientHello* y *ServerHello*) tiene una estructura de bytes fija y **no está cifrada** — solo los datos de aplicación se cifran después de negociar las claves. El primer byte del registro TLS es siempre `0x16` (Content Type: Handshake), seguido de la versión del protocolo (`0x03 0x01` para TLS 1.0, `0x03 0x03` para TLS 1.2/1.3). Detectando esta firma se puede confirmar que la sesión usa TLS incluso sin poder descifrar el contenido.

**Importante:** la herramienta **no descifra** el tráfico. Solo confirma la presencia del protocolo TLS a partir de metadatos (puerto) y la cabecera del handshake (no cifrada).

---

## 5.4 Componente de IA

### ¿Qué hace la componente de IA y qué resultados produce?

La componente de IA está implementada en `modules/ai_reporter.py`. Su función es transformar las estadísticas numéricas del análisis en un **informe narrativo técnico en español**, comprensible para estudiantes universitarios.

**Proceso:**
1. La herramienta recolecta todas las métricas TCP y UDP (sesiones, handshakes, estados, flujos, protocolos).
2. Construye un **prompt estructurado** en español con todos esos datos.
3. Envía el prompt a un modelo de lenguaje grande (LLM) externo vía API.
4. El LLM devuelve un análisis narrativo con seis secciones:
   - Resumen ejecutivo
   - Análisis TCP (handshakes, estados, cierres)
   - Análisis UDP (aplicaciones y propósito)
   - Protocolos y servicios identificados
   - Observaciones o anomalías
   - Conclusión vinculada a conceptos de Capa de Transporte OSI

**Proveedores soportados:**

| Proveedor | Modelo | Costo |
|---|---|---|
| Groq | llama-3.1-8b-instant | Gratuito |
| Google Gemini | gemini-2.0-flash | Gratuito (con cuota) |
| Anthropic | claude-sonnet-4-6 | Pago |
| Ollama | llama3 (local) | Gratuito (requiere GPU) |

Si ningún proveedor está disponible, la herramienta genera un **resumen automático basado en reglas** (sin IA externa), garantizando que siempre haya un informe.

---

### ¿Qué limitaciones tiene y qué mejoras propone el grupo?

**Limitaciones actuales:**

| Limitación | Descripción |
|---|---|
| Dependencia de API externa | Groq y Gemini requieren conexión a internet y una API key válida. Si la red falla o la cuota se agota, la IA no funciona. |
| Sin contexto del payload | La IA solo recibe estadísticas numéricas, no puede analizar el contenido de los paquetes directamente. |
| Modelos pequeños | Los modelos gratuitos (llama3-8b) tienen menor capacidad de razonamiento que modelos más grandes; pueden generar observaciones genéricas. |
| Sin memoria entre capturas | Cada análisis es independiente; la IA no puede comparar con capturas anteriores para detectar cambios en el tiempo. |
| Prompt en español fijo | El idioma del informe está hardcoded; no hay soporte para otros idiomas sin modificar el código. |
| Cuota de Gemini | La capa gratuita de Google AI Studio tiene límites de requests por minuto que pueden agotarse fácilmente. |

**Mejoras propuestas:**

1. **Modo offline con modelo local (Ollama):** integrar Ollama completamente para funcionar sin internet, usando modelos como `llama3` o `mistral` descargados localmente.
2. **Análisis comparativo:** guardar resultados de capturas anteriores y pedir a la IA que identifique cambios o tendencias.
3. **Detección de anomalías automatizada:** en lugar de solo narrar, que la IA clasifique el tráfico como "normal", "sospechoso" o "malicioso" según patrones conocidos.
4. **Soporte multilenguaje:** permitir seleccionar el idioma del informe con el argumento `--lang`.
5. **Exportación a PDF:** generar el informe narrativo junto con las gráficas en formato PDF además del HTML.
6. **Resumen ejecutivo más corto para presentaciones:** agregar una opción `--short` que solicite al LLM un informe de máximo 3 párrafos.
