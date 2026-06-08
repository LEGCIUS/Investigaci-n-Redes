"""
Módulo de IA — genera un informe narrativo usando múltiples proveedores.

Proveedores soportados (en orden de recomendación):
  - groq      : GRATUITO — llama3/mixtral via Groq Cloud (console.groq.com)
  - gemini    : GRATUITO — gemini-1.5-flash via Google AI Studio (aistudio.google.com)
  - anthropic : PAGO     — Claude via Anthropic API (console.anthropic.com)
  - ollama    : GRATIS   — modelos locales sin internet (ollama.com)
  - auto      : Prueba groq → gemini → anthropic → fallback automático
"""

import os
from typing import Optional


# ---------------------------------------------------------------------------
GROQ_MODELS    = ["llama3-8b-8192", "llama-3.1-8b-instant", "mixtral-8x7b-32768"]
GEMINI_MODEL   = "gemini-2.0-flash"
ANTHROPIC_MODEL= "claude-sonnet-4-6"
OLLAMA_MODEL   = "llama3"
OLLAMA_URL     = "http://localhost:11434/api/generate"


# ---------------------------------------------------------------------------
def _build_prompt(tcp: dict, udp: dict, protos: dict) -> str:
    tcp_protos = "\n".join(
        f"  - {p}: {c} sesiones" for p, c in list(protos["tcp_protocols"].items())[:10]
    ) or "  (ninguno)"
    udp_protos = "\n".join(
        f"  - {p}: {c} flujos" for p, c in list(protos["udp_protocols"].items())[:10]
    ) or "  (ninguno)"

    return f"""Eres un experto en análisis de redes (curso universitario IF5000 - Redes y Comunicación de Datos).
Analiza las siguientes estadísticas de una captura de tráfico de red y genera un informe técnico
en español, claro y detallado para estudiantes universitarios.

=== ESTADÍSTICAS TCP ===
- Sesiones TCP totales            : {tcp['total_sessions']}
- Three-way handshakes completos  : {tcp['complete_handshakes']}
- Conexiones incompletas (SYN)    : {tcp['incomplete_handshakes']}
- Cierres graceful (FIN-ACK)      : {tcp['graceful_closes']}
- Cierres abruptos (RST)          : {tcp['rst_closes']}
- Distribución por estado         : {tcp['sessions_by_state']}

=== ESTADÍSTICAS UDP ===
- Datagramas UDP totales          : {udp['total_datagrams']}
- Flujos únicos (4-tupla)         : {udp['total_flows']}
- Fuentes únicas (IP:puerto)      : {udp['unique_sources']}
- Destinos únicos (IP:puerto)     : {udp['unique_destinations']}

=== PROTOCOLOS DE APLICACIÓN DETECTADOS ===
TCP:
{tcp_protos}
UDP:
{udp_protos}

Genera un informe con estas secciones:
1. Resumen ejecutivo del tráfico capturado.
2. Análisis TCP: handshakes, estados de conexión, cierres FIN vs RST.
3. Análisis UDP: tipo de aplicaciones y su propósito.
4. Protocolos y servicios identificados.
5. Observaciones o anomalías (SYN sin respuesta, muchos RST, etc.).
6. Conclusión vinculada a conceptos de Capa de Transporte OSI.
"""


# ---------------------------------------------------------------------------
class AIReporter:
    """
    Genera el informe narrativo con el proveedor de IA configurado.
    Uso:
        reporter = AIReporter(api_key="...", provider="groq")
        text = reporter.generate_report(tcp, udp, protos)
    """

    def __init__(self, api_key: Optional[str] = None, provider: str = "auto"):
        self.api_key  = api_key or ""
        self.provider = provider.lower()

    # ------------------------------------------------------------------
    def generate_report(self, tcp: dict, udp: dict, protos: dict) -> str:
        prompt = _build_prompt(tcp, udp, protos)
        order  = self._resolve_order()

        for prov in order:
            result = self._try_provider(prov, prompt)
            if result:
                return result

        # Ningún proveedor funcionó — resumen automático
        return self._resumen_automatico(tcp, udp, protos)

    # ------------------------------------------------------------------
    def _resolve_order(self) -> list:
        if self.provider != "auto":
            return [self.provider]
        # Orden automático: probar según qué key está disponible
        order = []
        if self.api_key or os.environ.get("GROQ_API_KEY"):
            order.append("groq")
        if self.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            order.append("gemini")
        if self.api_key or os.environ.get("ANTHROPIC_API_KEY"):
            order.append("anthropic")
        order.append("ollama")  # siempre intentar ollama local como último recurso
        return order or ["ollama"]

    # ------------------------------------------------------------------
    def _try_provider(self, provider: str, prompt: str) -> Optional[str]:
        try:
            if provider == "groq":
                return self._groq(prompt)
            if provider == "gemini":
                return self._gemini(prompt)
            if provider == "anthropic":
                return self._anthropic(prompt)
            if provider == "ollama":
                return self._ollama(prompt)
        except Exception as exc:
            print(f"      [!] Proveedor '{provider}' falló: {exc}")
        return None

    # ------------------------------------------------------------------
    def _groq(self, prompt: str) -> str:
        from groq import Groq
        key = self.api_key or os.environ.get("GROQ_API_KEY", "")
        if not key:
            raise ValueError("GROQ_API_KEY no configurada")
        client = Groq(api_key=key)
        for model in GROQ_MODELS:
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=2048,
                )
                print(f"      [IA] Groq ({model}) respondio correctamente")
                return resp.choices[0].message.content
            except Exception:
                continue
        raise RuntimeError("Ningún modelo de Groq disponible")

    # ------------------------------------------------------------------
    def _gemini(self, prompt: str) -> str:
        from google import genai
        key = self.api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
        if not key:
            raise ValueError("GEMINI_API_KEY no configurada")
        client = genai.Client(api_key=key)
        resp   = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        print(f"      [IA] Gemini ({GEMINI_MODEL}) respondio correctamente")
        return resp.text

    # ------------------------------------------------------------------
    def _anthropic(self, prompt: str) -> str:
        import anthropic
        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY no configurada")
        client = anthropic.Anthropic(api_key=key)
        resp   = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )
        print(f"      [IA] Anthropic (Claude) respondio correctamente")
        return resp.content[0].text

    # ------------------------------------------------------------------
    def _ollama(self, prompt: str) -> str:
        import requests
        resp = requests.post(
            OLLAMA_URL,
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"      [IA] Ollama ({OLLAMA_MODEL}) respondio correctamente")
        return data.get("response", "")

    # ------------------------------------------------------------------
    def _resumen_automatico(self, tcp: dict, udp: dict, protos: dict) -> str:
        lines = []
        lines.append("INFORME AUTOMATICO - ANALISIS DE TRAFICO DE RED\n")
        lines.append("(Sin IA externa. Configura GROQ_API_KEY o GEMINI_API_KEY para analisis avanzado)\n")

        total = max(tcp["total_sessions"], 1)
        pct   = tcp["complete_handshakes"] / total * 100
        lines.append("-- PROTOCOLO TCP ---------------------------------------------------")
        lines.append(f"Se identificaron {tcp['total_sessions']} sesiones TCP.")
        lines.append(f"  * {tcp['complete_handshakes']} ({pct:.1f}%) completaron el three-way handshake (SYN->SYN-ACK->ACK).")
        if tcp["incomplete_handshakes"]:
            lines.append(f"  * {tcp['incomplete_handshakes']} conexiones incompletas (SYN sin respuesta).")
            lines.append("    Posible causa: escaneo de puertos, firewall o perdida de paquetes.")
        if tcp["rst_closes"]:
            lines.append(f"  * {tcp['rst_closes']} cierres abruptos (RST): terminacion forzada de conexion.")
        if tcp["graceful_closes"]:
            lines.append(f"  * {tcp['graceful_closes']} cierres graceful (FIN-ACK): terminacion ordenada.")
        lines.append("")

        lines.append("-- PROTOCOLO UDP ---------------------------------------------------")
        lines.append(f"Se capturaron {udp['total_datagrams']} datagramas UDP en {udp['total_flows']} flujos unicos.")
        lines.append(f"  * Origenes unicos  : {udp['unique_sources']}")
        lines.append(f"  * Destinos unicos  : {udp['unique_destinations']}")
        lines.append("  * UDP no tiene conexion: sin handshake ni garantia de entrega.")
        lines.append("")

        lines.append("-- PROTOCOLOS DE APLICACION ----------------------------------------")
        for proto, cnt in list(protos["all_protocols"].items())[:12]:
            lines.append(f"  * {proto:<30} {cnt:>5} sesiones/flujos")
        lines.append("")

        top3 = list(protos["all_protocols"].keys())[:3]
        lines.append("-- CONCLUSION ------------------------------------------------------")
        lines.append(f"Trafico principal: {', '.join(top3)}.")
        lines.append("La Capa de Transporte multiplexa flujos usando puertos,")
        lines.append("identificando sockets (IP:puerto) en cada extremo.")

        return "\n".join(lines)
