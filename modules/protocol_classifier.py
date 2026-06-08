"""
Módulo de Clasificación de Protocolos de Aplicación.

Estrategias (en orden de prioridad):
  1. Inspección por número de puerto (port-based classification).
  2. Inspección profunda de payload — firmas DPI (Deep Packet Inspection).
  3. Heurística por rango de puertos (well-known / registered / dynamic).

Referencia de puertos: RFC 1700 / IANA Service Name Registry.
"""

from collections import defaultdict
from typing import Dict, Optional

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.all import Raw
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Tabla de puertos bien conocidos (0–1023) y registrados frecuentes
PORT_MAP: Dict[int, str] = {
    20: "FTP-Data",   21: "FTP",         22: "SSH",
    23: "Telnet",     25: "SMTP",        53: "DNS",
    67: "DHCP",       68: "DHCP",        69: "TFTP",
    80: "HTTP",       110: "POP3",       119: "NNTP",
    123: "NTP",       143: "IMAP",       161: "SNMP",
    162: "SNMP-Trap", 179: "BGP",        389: "LDAP",
    443: "HTTPS",     445: "SMB",        465: "SMTPS",
    514: "Syslog",    587: "SMTP-Submit",636: "LDAPS",
    853: "DNS-TLS",   993: "IMAPS",      995: "POP3S",
    1080: "SOCKS",    1194: "OpenVPN",   1433: "MSSQL",
    1521: "Oracle-DB",3306: "MySQL",     3389: "RDP",
    5060: "SIP",      5061: "SIPS",      5432: "PostgreSQL",
    5900: "VNC",      6379: "Redis",     8080: "HTTP-Alt",
    8443: "HTTPS-Alt",27017: "MongoDB",  4444: "Metasploit",
    6667: "IRC",      1900: "SSDP/UPnP", 5353: "mDNS",
}

# ---------------------------------------------------------------------------
# Firmas de payload (primeros bytes) para DPI
PAYLOAD_SIGNATURES = [
    (b"HTTP/",    "HTTP"),
    (b"GET ",     "HTTP"),
    (b"POST ",    "HTTP"),
    (b"PUT ",     "HTTP"),
    (b"DELETE ",  "HTTP"),
    (b"HEAD ",    "HTTP"),
    (b"OPTIONS ", "HTTP"),
    (b"HTTP/2",   "HTTP/2"),
    (b"\x16\x03\x00", "TLS/HTTPS"),   # TLS 1.0 handshake
    (b"\x16\x03\x01", "TLS/HTTPS"),   # TLS 1.0
    (b"\x16\x03\x02", "TLS/HTTPS"),   # TLS 1.1
    (b"\x16\x03\x03", "TLS/HTTPS"),   # TLS 1.2
    (b"\x16\x03\x04", "TLS/HTTPS"),   # TLS 1.3
    (b"SSH-",     "SSH"),
    (b"220 ",     "FTP/SMTP"),
    (b"USER ",    "FTP"),
    (b"EHLO ",    "SMTP"),
    (b"HELO ",    "SMTP"),
    (b"MAIL FROM", "SMTP"),
    (b"\x00\x00\x00\x00", "DNS"),     # DNS query (approx)
    (b"NTLMSSP", "NTLM/SMB"),
    (b"\x00\x00\x00\x00\x00\x00",    "RTP/Media"),  # RTP/RTCP hint
    (b"CONNECT ", "HTTP-CONNECT"),
    (b"UPGRADE ", "WebSocket"),
]


# ---------------------------------------------------------------------------
class ProtocolClassifier:
    """Clasifica sesiones TCP y flujos UDP según el protocolo de aplicación."""

    def __init__(self, packets, tcp_results: dict, udp_results: dict):
        self.packets    = packets
        self.tcp_res    = tcp_results
        self.udp_res    = udp_results
        self._payload_cache: Dict = {}   # key → protocol desde DPI

    # ------------------------------------------------------------------
    def _by_port(self, port: int) -> Optional[str]:
        return PORT_MAP.get(port)

    def _by_payload(self, payload: bytes) -> Optional[str]:
        for signature, proto in PAYLOAD_SIGNATURES:
            if payload[:len(signature)] == signature:
                return proto
        return None

    def _classify_ports(self, port_a: int, port_b: int) -> str:
        """Intenta clasificar usando el puerto menor (generalmente el servidor)."""
        for p in sorted([port_a, port_b]):
            hit = self._by_port(p)
            if hit:
                return hit
        # Heurística por rango
        min_p = min(port_a, port_b)
        if min_p < 1024:
            return f"Desconocido-WellKnown({min_p})"
        if min_p < 49152:
            return f"Desconocido-Registrado({min_p})"
        return "Dinámico/Privado"

    # ------------------------------------------------------------------
    @staticmethod
    def _tcp_session_key(ip1, p1, ip2, p2):
        """Misma lógica de normalización que TCPAnalyzer._clave_sesion."""
        ep1, ep2 = (ip1, p1), (ip2, p2)
        return (min(ep1, ep2), max(ep1, ep2))

    def _build_payload_cache(self):
        """Pre-procesa paquetes con payload para DPI por sesión/flujo."""
        for pkt in self.packets:
            if Raw not in pkt:
                continue
            if IP not in pkt:
                continue

            payload = bytes(pkt[Raw].load)
            if len(payload) < 4:
                continue

            proto_dpi = self._by_payload(payload)
            if not proto_dpi:
                continue

            ip = pkt[IP]
            if TCP in pkt:
                tcp = pkt[TCP]
                key = self._tcp_session_key(ip.src, tcp.sport, ip.dst, tcp.dport)
            elif UDP in pkt:
                udp = pkt[UDP]
                key = (ip.src, udp.sport, ip.dst, udp.dport)
            else:
                continue

            # Solo sobrescribir si aún no está clasificado
            if key not in self._payload_cache:
                self._payload_cache[key] = proto_dpi

    # ------------------------------------------------------------------
    def classify(self) -> dict:
        self._build_payload_cache()

        tcp_proto_counts: Dict[str, int] = defaultdict(int)
        udp_proto_counts: Dict[str, int] = defaultdict(int)

        # Clasificar sesiones TCP
        for key, ses in self.tcp_res["sessions"].items():
            # 1) DPI
            proto = self._payload_cache.get(key)
            # 2) Puerto
            if not proto:
                proto = self._classify_ports(ses.src_port, ses.dst_port)
            ses.protocol = proto
            tcp_proto_counts[proto] += 1

        # Clasificar flujos UDP
        for key, flow in self.udp_res["flows"].items():
            # DPI key para UDP es la 4-tupla unidireccional
            proto = self._payload_cache.get(key)
            if not proto:
                proto = self._classify_ports(flow.src_port, flow.dst_port)
            flow.protocol = proto
            udp_proto_counts[proto] += 1

        all_protos: Dict[str, int] = defaultdict(int)
        for p, c in tcp_proto_counts.items():
            all_protos[p] += c
        for p, c in udp_proto_counts.items():
            all_protos[p] += c

        return {
            "tcp_protocols": dict(sorted(tcp_proto_counts.items(), key=lambda x: x[1], reverse=True)),
            "udp_protocols": dict(sorted(udp_proto_counts.items(), key=lambda x: x[1], reverse=True)),
            "all_protocols": dict(sorted(all_protos.items(),       key=lambda x: x[1], reverse=True)),
        }
