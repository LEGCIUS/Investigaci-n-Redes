"""
Módulo TCP — reconstrucción de sesiones y análisis del ciclo de vida.

Máquina de estados simplificada:
  NONE → (SYN) → SYN_ENVIADO
  SYN_ENVIADO → (SYN+ACK) → SYN_RECIBIDO
  SYN_RECIBIDO → (ACK) → COMPLETO   (three-way handshake completo)
  cualquier estado → (RST) → RESET
  COMPLETO → (FIN×2) → CERRADA_FIN
"""

from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from typing import Dict, Tuple, List

try:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Packet
except ImportError:
    pass


# ---------------------------------------------------------------------------
class HandshakeState(Enum):
    NONE = "SIN_HANDSHAKE"
    SYN_ENVIADO = "SYN_ENVIADO"
    SYN_RECIBIDO = "SYN_RECIBIDO"
    COMPLETO = "COMPLETO"


# ---------------------------------------------------------------------------
@dataclass
class TCPSession:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str = "Desconocido"

    # Three-way handshake
    hs_state: HandshakeState = HandshakeState.NONE
    handshake_complete: bool = False

    # Cierre de conexión
    fin_count: int = 0        # número de FIN vistos (uno por lado = 2 para cierre completo)
    rst_seen: bool = False
    graceful_close: bool = False

    # Estadísticas
    packet_count: int = 0
    byte_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def estado(self) -> str:
        if self.rst_seen:
            return "RESET"
        if self.graceful_close:
            return "CERRADA_FIN"
        if self.handshake_complete:
            return "ESTABLECIDA"
        if self.hs_state == HandshakeState.SYN_RECIBIDO:
            return "SYN_ACK_VISTO"
        if self.hs_state == HandshakeState.SYN_ENVIADO:
            return "SYN_INCOMPLETO"
        return "SOLO_DATOS"

    @property
    def duracion(self) -> float:
        if self.end_time > self.start_time:
            return round(self.end_time - self.start_time, 4)
        return 0.0


# ---------------------------------------------------------------------------
class TCPAnalyzer:
    """Analiza todos los paquetes TCP y reconstruye sesiones."""

    def __init__(self, packets):
        self.packets = packets
        self.sessions: Dict[Tuple, TCPSession] = {}

    # ------------------------------------------------------------------
    @staticmethod
    def _clave_sesion(ip1: str, p1: int, ip2: str, p2: int) -> Tuple:
        """Clave normalizada: siempre (menor_endpoint, mayor_endpoint)."""
        ep1, ep2 = (ip1, p1), (ip2, p2)
        return (min(ep1, ep2), max(ep1, ep2))

    # ------------------------------------------------------------------
    def _procesar_paquete(self, pkt) -> None:
        if IP not in pkt or TCP not in pkt:
            return

        ip  = pkt[IP]
        tcp = pkt[TCP]
        src_ip, dst_ip   = ip.src, ip.dst
        src_pt, dst_pt   = tcp.sport, tcp.dport
        ts               = float(pkt.time)

        key = self._clave_sesion(src_ip, src_pt, dst_ip, dst_pt)

        if key not in self.sessions:
            self.sessions[key] = TCPSession(
                src_ip=src_ip, src_port=src_pt,
                dst_ip=dst_ip, dst_port=dst_pt,
                start_time=ts,
            )

        ses = self.sessions[key]
        ses.packet_count += 1
        ses.byte_count   += len(pkt)
        ses.end_time      = ts

        flags  = int(tcp.flags)
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)
        is_fin = bool(flags & 0x01)
        is_rst = bool(flags & 0x04)

        # RST — cierre abrupto inmediato
        if is_rst:
            ses.rst_seen = True
            return

        # FIN — cierre graceful cuando ambos lados envían FIN
        if is_fin:
            ses.fin_count += 1
            if ses.fin_count >= 2:
                ses.graceful_close = True

        # ---- Máquina de estados del handshake ----
        if is_syn and not is_ack:
            # SYN puro: iniciación de conexión
            if ses.hs_state == HandshakeState.NONE:
                ses.hs_state = HandshakeState.SYN_ENVIADO

        elif is_syn and is_ack:
            # SYN-ACK: respuesta del servidor
            if ses.hs_state == HandshakeState.SYN_ENVIADO:
                ses.hs_state = HandshakeState.SYN_RECIBIDO

        elif is_ack and not is_syn:
            # ACK puro: puede completar el handshake
            if ses.hs_state == HandshakeState.SYN_RECIBIDO and not ses.handshake_complete:
                ses.handshake_complete = True
                ses.hs_state = HandshakeState.COMPLETO

    # ------------------------------------------------------------------
    def analyze(self) -> dict:
        for pkt in self.packets:
            self._procesar_paquete(pkt)
        return self._compilar_resultados()

    # ------------------------------------------------------------------
    def _compilar_resultados(self) -> dict:
        ss = self.sessions.values()
        total             = len(self.sessions)
        hs_completos      = sum(1 for s in ss if s.handshake_complete)
        hs_incompletos    = sum(1 for s in ss if s.hs_state == HandshakeState.SYN_ENVIADO and not s.handshake_complete)
        cierres_graceful  = sum(1 for s in ss if s.graceful_close)
        cierres_rst       = sum(1 for s in ss if s.rst_seen)

        estados = defaultdict(int)
        for s in ss:
            estados[s.estado] += 1

        top10 = sorted(self.sessions.values(), key=lambda s: s.byte_count, reverse=True)[:10]

        return {
            "total_sessions":        total,
            "complete_handshakes":   hs_completos,
            "incomplete_handshakes": hs_incompletos,
            "graceful_closes":       cierres_graceful,
            "rst_closes":            cierres_rst,
            "sessions_by_state":     dict(estados),
            "sessions":              self.sessions,
            "top_sessions":          top10,
        }
