#!/usr/bin/env python3
"""
Analizador de Tráfico de Red — Capa de Transporte OSI (TCP/UDP)
UCR IF5000 — Redes y Comunicación de Datos

Uso:
  python main.py captura.pcapng
  python main.py captura.pcapng --output html
  python main.py captura.pcapng --ai --api-key TU_CLAVE
  python main.py captura.pcapng --output both --ai
"""

import argparse
import os
import sys
from pathlib import Path

# Forzar UTF-8 en stdout/stderr para compatibilidad con Windows y caracteres especiales
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ── importar módulos locales ──────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from modules.ingestion           import PacketIngestion
from modules.tcp_analyzer        import TCPAnalyzer
from modules.udp_analyzer        import UDPAnalyzer
from modules.protocol_classifier import ProtocolClassifier
from modules.ai_reporter         import AIReporter
from modules.report_generator    import ReportGenerator


# ---------------------------------------------------------------------------
def _banner():
    print()
    print("=" * 68)
    print("  ANALIZADOR DE TRÁFICO DE RED — CAPA DE TRANSPORTE OSI")
    print("  UCR IF5000 — Redes y Comunicación de Datos")
    print("=" * 68)


def _check_deps():
    missing = []
    for pkg in ("scapy", "colorama", "jinja2"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Dependencias faltantes: {', '.join(missing)}")
        print(f"    Instálalas con: pip install {' '.join(missing)}")
        sys.exit(1)


# ---------------------------------------------------------------------------
def main():
    _check_deps()

    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Analiza capturas .pcap/.pcapng — Capa de Transporte OSI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Proveedores de IA soportados (--provider):
  groq      GRATUITO  console.groq.com       -> set GROQ_API_KEY=gsk_...
  gemini    GRATUITO  aistudio.google.com    -> set GEMINI_API_KEY=AIza...
  anthropic PAGO      console.anthropic.com  -> set ANTHROPIC_API_KEY=sk-ant-...
  ollama    GRATIS    local, sin internet    -> instala ollama.com

Ejemplos:
  python main.py captura.pcapng
  python main.py captura.pcapng --output html
  python main.py captura.pcapng --output both --ai --provider groq --api-key gsk_...
  python main.py captura.pcapng --output both --ai --provider gemini --api-key AIza...
        """,
    )
    parser.add_argument("pcap_file",
                        help="Ruta al archivo de captura (.pcap o .pcapng)")
    parser.add_argument("--output", choices=["console", "html", "both"],
                        default="console",
                        help="Formato de salida (default: console)")
    parser.add_argument("--html-output", default="reporte.html",
                        metavar="FILE",
                        help="Nombre del archivo HTML (default: reporte.html)")
    parser.add_argument("--ai", action="store_true",
                        help="Activar analisis narrativo con IA")
    parser.add_argument("--provider",
                        choices=["groq", "gemini", "anthropic", "ollama", "auto"],
                        default="auto",
                        help="Proveedor de IA (default: auto)")
    parser.add_argument("--api-key", metavar="KEY",
                        help="API key del proveedor elegido")

    args = parser.parse_args()

    # ── Validar archivo ───────────────────────────────────────────────────
    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        print(f"\n[!] Error: archivo no encontrado: {pcap_path}")
        sys.exit(1)

    _banner()
    size_kb = pcap_path.stat().st_size / 1024
    print(f"\n  Archivo : {pcap_path.name}")
    print(f"  Tamaño  : {size_kb:.1f} KB")
    print()

    # ── 1. Ingesta ────────────────────────────────────────────────────────
    print("[1/5] Cargando y parseando paquetes...")
    ingest  = PacketIngestion(str(pcap_path))
    packets = ingest.load()
    stats   = ingest.get_stats()
    print(f"      [OK] Total: {stats['total']}  |  TCP: {stats['tcp']}  |  UDP: {stats['udp']}  |  Otros: {stats['other']}")

    if stats["total"] == 0:
        print("\n[!] El archivo no contiene paquetes válidos. Verifica el archivo.")
        sys.exit(0)

    # ── 2. Análisis TCP ───────────────────────────────────────────────────
    print("\n[2/5] Analizando sesiones TCP (reconstrucción de ciclo de vida)...")
    tcp_analyzer = TCPAnalyzer(packets)
    tcp_results  = tcp_analyzer.analyze()
    print(f"      [OK] Sesiones: {tcp_results['total_sessions']}  |"
          f"  Handshakes completos: {tcp_results['complete_handshakes']}  |"
          f"  RST: {tcp_results['rst_closes']}  |"
          f"  FIN graceful: {tcp_results['graceful_closes']}")

    # ── 3. Análisis UDP ───────────────────────────────────────────────────
    print("\n[3/5] Analizando datagramas UDP...")
    udp_analyzer = UDPAnalyzer(packets)
    udp_results  = udp_analyzer.analyze()
    print(f"      [OK] Datagramas: {udp_results['total_datagrams']}  |"
          f"  Flujos únicos: {udp_results['total_flows']}  |"
          f"  Fuentes: {udp_results['unique_sources']}  |"
          f"  Destinos: {udp_results['unique_destinations']}")

    # ── 4. Clasificación de protocolos ────────────────────────────────────
    print("\n[4/5] Clasificando protocolos de aplicación (port-based + DPI)...")
    classifier       = ProtocolClassifier(packets, tcp_results, udp_results)
    protocol_results = classifier.classify()
    top5 = list(protocol_results["all_protocols"].keys())[:5]
    print(f"      [OK] Protocolos detectados: {', '.join(top5) if top5 else '(ninguno)'}")

    # ── 5. IA ─────────────────────────────────────────────────────────────
    ai_narrative = None
    print("\n[5/5] Generando informe...")

    if args.ai:
        provider = args.provider
        api_key  = args.api_key or ""

        # Auto-detectar key desde variables de entorno si no se pasó --api-key
        if not api_key:
            if provider in ("groq", "auto"):
                api_key = os.environ.get("GROQ_API_KEY", "")
            if not api_key and provider in ("gemini", "auto"):
                api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY", "")
            if not api_key and provider in ("anthropic", "auto"):
                api_key = os.environ.get("ANTHROPIC_API_KEY", "")

        prov_label = provider if provider != "auto" else "auto (groq/gemini/anthropic/ollama)"
        print(f"      Proveedor: {prov_label}")
        print("      Consultando IA para analisis narrativo...")
        reporter     = AIReporter(api_key=api_key, provider=provider)
        ai_narrative = reporter.generate_report(tcp_results, udp_results, protocol_results)
        print("      [OK] Informe IA listo")
    else:
        print("      (Usa --ai para activar el análisis narrativo con IA)")

    # ── Generación del reporte ────────────────────────────────────────────
    gen = ReportGenerator(tcp_results, udp_results, protocol_results,
                          ai_narrative, ai_provider=args.provider if args.ai else "IA")

    if args.output in ("console", "both"):
        gen.print_console()

    if args.output in ("html", "both"):
        gen.generate_html(args.html_output)
        print(f"\n[[OK]] Reporte HTML guardado en: {args.html_output}")
        print(f"    Ábrelo en tu navegador para visualizarlo con gráficas interactivas.")

    print("\n[[OK]] Análisis completado exitosamente.\n")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    main()
