"""
Módulo UDP — conteo de datagramas agrupados por par (src_ip:src_port → dst_ip:dst_port).

UDP no tiene conexión, por lo que cada datagrama es independiente.
Se agrupan por flujo unidireccional (4-tupla exacta) para distinguir origen y destino.
"""

from dataclasses import dataclass
from typing import Dict, Tuple

try:
    from scapy.layers.inet import IP, UDP
except ImportError:
    pass


# ---------------------------------------------------------------------------
@dataclass
class UDPFlow:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "Desconocido"
    datagram_count: int = 0
    byte_count: int = 0


# ---------------------------------------------------------------------------
class UDPAnalyzer:
    """Analiza paquetes UDP y construye estadísticas por flujo."""

    def __init__(self, packets):
        self.packets = packets
        # Clave: (src_ip, src_port, dst_ip, dst_port) — unidireccional
        self.flows: Dict[Tuple, UDPFlow] = {}

    # ------------------------------------------------------------------
    def analyze(self) -> dict:
        for pkt in self.packets:
            if IP not in pkt or UDP not in pkt:
                continue

            ip  = pkt[IP]
            udp = pkt[UDP]
            key = (ip.src, udp.sport, ip.dst, udp.dport)

            if key not in self.flows:
                self.flows[key] = UDPFlow(
                    src_ip=ip.src, src_port=udp.sport,
                    dst_ip=ip.dst, dst_port=udp.dport,
                )

            self.flows[key].datagram_count += 1
            self.flows[key].byte_count     += len(pkt)

        return self._compilar_resultados()

    # ------------------------------------------------------------------
    def _compilar_resultados(self) -> dict:
        total_datagrams = sum(f.datagram_count for f in self.flows.values())
        total_flows     = len(self.flows)
        unique_src      = len({(f.src_ip, f.src_port) for f in self.flows.values()})
        unique_dst      = len({(f.dst_ip, f.dst_port) for f in self.flows.values()})

        top10 = sorted(self.flows.values(), key=lambda f: f.datagram_count, reverse=True)[:10]

        return {
            "total_datagrams":    total_datagrams,
            "total_flows":        total_flows,
            "unique_sources":     unique_src,
            "unique_destinations": unique_dst,
            "flows":              self.flows,
            "top_flows":          top10,
        }
