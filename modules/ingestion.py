"""
Módulo de Ingesta — carga y parseo de archivos .pcap / .pcapng con scapy.
"""

import sys
from pathlib import Path

try:
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    # PcapNGReader no está disponible en todas las versiones de scapy
    try:
        from scapy.utils import PcapNGReader as _PcapNGReader
        _HAS_PCAPNG_READER = True
    except ImportError:
        _HAS_PCAPNG_READER = False
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
    _HAS_PCAPNG_READER = False


class PacketIngestion:
    """Carga un archivo de captura y separa los paquetes TCP y UDP."""

    def __init__(self, filepath: str):
        if not SCAPY_OK:
            print("[!] scapy no está instalado. Ejecuta: pip install scapy")
            sys.exit(1)

        self.filepath = filepath
        self.packets = []
        self.tcp_packets = []
        self.udp_packets = []

    # ------------------------------------------------------------------
    def load(self):
        """Lee el archivo y devuelve la lista completa de paquetes."""
        path = Path(self.filepath)
        suffix = path.suffix.lower()

        try:
            if suffix == ".pcapng" and _HAS_PCAPNG_READER:
                try:
                    with _PcapNGReader(str(path)) as reader:
                        self.packets = list(reader)
                except Exception:
                    self.packets = list(rdpcap(str(path)))
            else:
                # rdpcap soporta pcap y pcapng en versiones modernas de scapy
                self.packets = list(rdpcap(str(path)))
        except FileNotFoundError:
            print(f"[!] Archivo no encontrado: {self.filepath}")
            sys.exit(1)
        except Exception as exc:
            print(f"[!] Error al leer el archivo de captura: {exc}")
            sys.exit(1)

        for pkt in self.packets:
            if IP in pkt:
                if TCP in pkt:
                    self.tcp_packets.append(pkt)
                elif UDP in pkt:
                    self.udp_packets.append(pkt)

        return self.packets

    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        total = len(self.packets)
        tcp_n = len(self.tcp_packets)
        udp_n = len(self.udp_packets)
        return {
            "total": total,
            "tcp": tcp_n,
            "udp": udp_n,
            "other": total - tcp_n - udp_n,
        }
