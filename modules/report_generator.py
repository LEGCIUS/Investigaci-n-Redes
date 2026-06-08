"""
Módulo de Reporte — salida en consola (color) y HTML interactivo con Chart.js.
"""

import json
from datetime import datetime
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORAMA_OK = True
except ImportError:
    COLORAMA_OK = False

try:
    from jinja2 import Template
    JINJA2_OK = True
except ImportError:
    JINJA2_OK = False


# ---------------------------------------------------------------------------
def _color(text: str, code: str) -> str:
    if not COLORAMA_OK:
        return text
    return f"{code}{text}{Style.RESET_ALL}"


def _cyan(t):   return _color(t, Fore.CYAN)
def _yellow(t): return _color(t, Fore.YELLOW)
def _green(t):  return _color(t, Fore.GREEN)
def _magenta(t):return _color(t, Fore.MAGENTA)
def _blue(t):   return _color(t, Fore.BLUE)
def _red(t):    return _color(t, Fore.RED)


# ---------------------------------------------------------------------------
class ReportGenerator:

    def __init__(self, tcp: dict, udp: dict, protos: dict,
                 ai_narrative: Optional[str] = None, ai_provider: str = "IA"):
        self.tcp         = tcp
        self.udp         = udp
        self.protos      = protos
        self.ai          = ai_narrative
        self.ai_provider = ai_provider.upper() if ai_provider != "auto" else "IA"
        self.ts          = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -----------------------------------------------------------------------
    #  CONSOLA
    # -----------------------------------------------------------------------
    def print_console(self):
        sep = "=" * 72
        hr  = "-" * 72

        print()
        print(_cyan(sep))
        print(_cyan("  ANALISIS DE TRAFICO DE RED - CAPA DE TRANSPORTE OSI"))
        print(_cyan(f"  Generado: {self.ts}"))
        print(_cyan(sep))

        # TCP
        print()
        print(_yellow(f"+-- PROTOCOLO TCP {'-' * 55}"))
        print(_yellow(f"|  Sesiones TCP totales              : {self.tcp['total_sessions']:>8}"))
        print(_yellow(f"|  Three-way handshakes completos    : {self.tcp['complete_handshakes']:>8}"))
        print(_yellow(f"|  Conexiones incompletas (SYN)      : {self.tcp['incomplete_handshakes']:>8}"))
        print(_yellow(f"|  Cierres graceful (FIN-ACK)        : {self.tcp['graceful_closes']:>8}"))
        print(_yellow(f"|  Cierres abruptos (RST)            : {self.tcp['rst_closes']:>8}"))
        print(_yellow("|"))
        print(_yellow("|  Distribucion por estado:"))
        for estado, cnt in sorted(self.tcp["sessions_by_state"].items(), key=lambda x: x[1], reverse=True):
            bar = "#" * min(int(cnt / max(self.tcp["total_sessions"], 1) * 30), 30)
            print(_yellow(f"|    {estado:<25} {cnt:>6}  {bar}"))
        print(_yellow("|"))
        if self.tcp["sessions_by_state"].get("SOLO_DATOS", 0) > 0:
            n = self.tcp["sessions_by_state"]["SOLO_DATOS"]
            print(_yellow(f"|  Nota: {n} sesion(es) en estado SOLO_DATOS = la captura inicio con"))
            print(_yellow("|        esas conexiones ya establecidas (handshake ocurrio antes de capturar)."))
            print(_yellow("|"))
        print(_yellow("|  Top 10 sesiones por volumen de trafico:"))
        hdr = f"|    {'Origen':<22} {'Destino':<22} {'Pkts':>6} {'Bytes':>9} {'Dur(s)':>7}  {'Estado':<18} {'Protocolo'}"
        print(_yellow(hdr))
        print(_yellow("|  " + "-" * 98))
        for s in self.tcp["top_sessions"]:
            proto   = getattr(s, "protocol", "?")
            origen  = f"{s.src_ip}:{s.src_port}"
            destino = f"{s.dst_ip}:{s.dst_port}"
            print(_yellow(f"|    {origen:<22} {destino:<22} {s.packet_count:>6} {s.byte_count:>9} {s.duracion:>7.3f}  {s.estado:<18} {proto}"))
        print(_yellow(f"+{'-' * 71}"))

        # UDP
        print()
        print(_green(f"+-- PROTOCOLO UDP {'-' * 55}"))
        print(_green(f"|  Datagramas UDP totales            : {self.udp['total_datagrams']:>8}"))
        print(_green(f"|  Flujos unicos (src:port->dst:port): {self.udp['total_flows']:>8}"))
        print(_green(f"|  Fuentes unicas (IP:puerto)        : {self.udp['unique_sources']:>8}"))
        print(_green(f"|  Destinos unicos (IP:puerto)       : {self.udp['unique_destinations']:>8}"))
        print(_green("|"))
        print(_green("|  Top 10 flujos por numero de datagramas:"))
        hdr2 = f"|    {'Origen':<22} {'Destino':<22} {'Datagrams':>10} {'Bytes':>9}  {'Protocolo'}"
        print(_green(hdr2))
        print(_green("|  " + "-" * 78))
        for f in self.udp["top_flows"]:
            proto   = getattr(f, "protocol", "?")
            origen  = f"{f.src_ip}:{f.src_port}"
            destino = f"{f.dst_ip}:{f.dst_port}"
            print(_green(f"|    {origen:<22} {destino:<22} {f.datagram_count:>10} {f.byte_count:>9}  {proto}"))
        print(_green(f"+{'-' * 71}"))

        # Protocolos
        print()
        print(_magenta(f"+-- PROTOCOLOS DE APLICACION IDENTIFICADOS {'-' * 30}"))
        max_tcp = max(self.protos["tcp_protocols"].values(), default=1)
        max_udp = max(self.protos["udp_protocols"].values(), default=1)
        print(_magenta("|  TCP:"))
        for proto, cnt in list(self.protos["tcp_protocols"].items())[:15]:
            bar = "#" * min(int(cnt / max_tcp * 35), 35)
            print(_magenta(f"|    {proto:<28} {cnt:>6}  {bar}"))
        print(_magenta("|"))
        print(_magenta("|  UDP:"))
        for proto, cnt in list(self.protos["udp_protocols"].items())[:10]:
            bar = "#" * min(int(cnt / max_udp * 35), 35)
            print(_magenta(f"|    {proto:<28} {cnt:>6}  {bar}"))
        print(_magenta(f"+{'-' * 71}"))

        # IA
        if self.ai:
            print()
            print(_blue(f"+-- ANALISIS CON INTELIGENCIA ARTIFICIAL ({self.ai_provider}) {'-' * (31 - len(self.ai_provider))}"))
            for line in self.ai.split("\n"):
                print(_blue(f"|  {line}"))
            print(_blue(f"+{'-' * 71}"))

        print()
        print(_cyan(sep))
        print(_cyan("  Analisis completado."))
        print(_cyan(sep))
        print()

    # -----------------------------------------------------------------------
    #  HTML
    # -----------------------------------------------------------------------
    def generate_html(self, output_path: str):
        if not JINJA2_OK:
            print("[!] jinja2 no disponible. Ejecuta: pip install jinja2")
            return

        tcp_sessions_list = []
        for s in self.tcp["top_sessions"]:
            tcp_sessions_list.append({
                "src":      f"{s.src_ip}:{s.src_port}",
                "dst":      f"{s.dst_ip}:{s.dst_port}",
                "packets":  s.packet_count,
                "bytes":    s.byte_count,
                "state":    s.estado,
                "protocol": getattr(s, "protocol", "?"),
                "duration": f"{s.duracion:.3f}s",
            })

        udp_flows_list = []
        for f in self.udp["top_flows"]:
            udp_flows_list.append({
                "src":       f"{f.src_ip}:{f.src_port}",
                "dst":       f"{f.dst_ip}:{f.dst_port}",
                "datagrams": f.datagram_count,
                "bytes":     f.byte_count,
                "protocol":  getattr(f, "protocol", "?"),
            })

        tpl = Template(_HTML_TEMPLATE)
        html = tpl.render(
            ts              = self.ts,
            tcp             = self.tcp,
            udp             = self.udp,
            protos          = self.protos,
            tcp_sessions    = tcp_sessions_list,
            udp_flows       = udp_flows_list,
            ai_narrative    = self.ai,
            ai_provider     = self.ai_provider,
            tcp_proto_json  = json.dumps(self.protos.get("tcp_protocols", {})),
            udp_proto_json  = json.dumps(self.protos.get("udp_protocols", {})),
            states_json     = json.dumps(self.tcp.get("sessions_by_state", {})),
        )

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(html)


# ---------------------------------------------------------------------------
#  PLANTILLA HTML (Bootstrap 5 + Chart.js — sin dependencias locales)
# ---------------------------------------------------------------------------
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Análisis de Tráfico de Red</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<style>
  body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',sans-serif}
  .card{background:#161b22;border:1px solid #30363d;border-radius:10px}
  .card-header{background:#21262d;border-bottom:1px solid #30363d;font-weight:600}
  .stat-num{font-size:2.2rem;font-weight:700}
  .table{color:#c9d1d9}
  .table thead th{background:#21262d;color:#8b949e;border-color:#30363d}
  .table td{border-color:#21262d}
  .table-hover tbody tr:hover td{background:#1c2128}
  .badge-RESET{background:#4a0d0d;color:#f85149}
  .badge-ESTABLECIDA{background:#0d4a1a;color:#56d364}
  .badge-CERRADA_FIN{background:#1c2d40;color:#58a6ff}
  .badge-SYN_INCOMPLETO{background:#3d2b00;color:#f0883e}
  .badge-SYN_ACK_VISTO{background:#2d2b00;color:#e3b341}
  .badge-SOLO_DATOS{background:#21262d;color:#8b949e}
  .ai-box{background:#0d1f38;border:1px solid #1f6feb;border-radius:10px;white-space:pre-wrap;line-height:1.7}
  a,a:hover{color:#58a6ff}
  h2,h3{color:#58a6ff}
  .text-muted{color:#8b949e!important}
  code{color:#f0883e}
</style>
</head>
<body>
<nav class="navbar" style="background:#161b22;border-bottom:1px solid #30363d">
  <div class="container-fluid">
    <span class="navbar-brand text-white fw-bold">Analizador de Trafico de Red</span>
    <span class="text-muted small">UCR IF5000 — Capa de Transporte OSI | {{ ts }}</span>
  </div>
</nav>

<div class="container-xl py-4">

  <!-- KPI cards -->
  <div class="row g-3 mb-4">
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#58a6ff">{{ tcp.total_sessions }}</div>
        <div class="text-muted small">Sesiones TCP</div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#56d364">{{ tcp.complete_handshakes }}</div>
        <div class="text-muted small">Handshakes OK</div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#f0883e">{{ tcp.incomplete_handshakes }}</div>
        <div class="text-muted small">SYN sin resp.</div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#f85149">{{ tcp.rst_closes }}</div>
        <div class="text-muted small">Cierres RST</div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#3fb950">{{ udp.total_datagrams }}</div>
        <div class="text-muted small">Datagramas UDP</div>
      </div>
    </div>
    <div class="col-6 col-md-2">
      <div class="card p-3 text-center">
        <div class="stat-num" style="color:#79c0ff">{{ udp.total_flows }}</div>
        <div class="text-muted small">Flujos UDP</div>
      </div>
    </div>
  </div>

  <!-- Charts row -->
  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="card p-3 h-100">
        <div class="card-header mb-3">Estados TCP</div>
        <canvas id="chartStates" height="220"></canvas>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3 h-100">
        <div class="card-header mb-3">Protocolos TCP (Top 10)</div>
        <canvas id="chartTCP" height="220"></canvas>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3 h-100">
        <div class="card-header mb-3">Protocolos UDP (Top 10)</div>
        <canvas id="chartUDP" height="220"></canvas>
      </div>
    </div>
  </div>

  <!-- TCP Table -->
  <div class="card mb-4">
    <div class="card-header p-3">Sesiones TCP - Top 10 por volumen de trafico</div>
    <div class="table-responsive">
      <table class="table table-hover mb-0">
        <thead>
          <tr>
            <th>Origen (socket)</th><th>Destino (socket)</th>
            <th>Paquetes</th><th>Bytes</th><th>Duración</th>
            <th>Estado</th><th>Protocolo App</th>
          </tr>
        </thead>
        <tbody>
        {% for s in tcp_sessions %}
          <tr>
            <td><code>{{ s.src }}</code></td>
            <td><code>{{ s.dst }}</code></td>
            <td>{{ s.packets }}</td>
            <td>{{ s.bytes }}</td>
            <td>{{ s.duration }}</td>
            <td><span class="badge badge-{{ s.state }}">{{ s.state }}</span></td>
            <td><strong>{{ s.protocol }}</strong></td>
          </tr>
        {% else %}
          <tr><td colspan="7" class="text-center text-muted">Sin sesiones TCP</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- UDP Table -->
  <div class="card mb-4">
    <div class="card-header p-3">Flujos UDP - Top 10 por numero de datagramas</div>
    <div class="table-responsive">
      <table class="table table-hover mb-0">
        <thead>
          <tr>
            <th>Origen (IP:Puerto)</th><th>Destino (IP:Puerto)</th>
            <th>Datagramas</th><th>Bytes</th><th>Protocolo App</th>
          </tr>
        </thead>
        <tbody>
        {% for f in udp_flows %}
          <tr>
            <td><code>{{ f.src }}</code></td>
            <td><code>{{ f.dst }}</code></td>
            <td>{{ f.datagrams }}</td>
            <td>{{ f.bytes }}</td>
            <td><strong>{{ f.protocol }}</strong></td>
          </tr>
        {% else %}
          <tr><td colspan="5" class="text-center text-muted">Sin flujos UDP</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  {% if ai_narrative %}
  <!-- AI Report -->
  <div class="ai-box p-4 mb-4">
    <h5 class="mb-3">Analisis con Inteligencia Artificial ({{ ai_provider }})</h5>
    {{ ai_narrative | e }}
  </div>
  {% endif %}

</div><!-- /container -->

<footer class="text-center py-3 text-muted small" style="border-top:1px solid #30363d">
  Herramienta de Análisis de Tráfico — UCR IF5000 Redes y Comunicación de Datos
</footer>

<script>
const CHART_OPTS = {
  plugins:{legend:{labels:{color:'#c9d1d9'}}},
  scales:{x:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}},
          y:{ticks:{color:'#8b949e'},grid:{color:'#21262d'}}}
};
const PIE_OPTS = {plugins:{legend:{position:'right',labels:{color:'#c9d1d9',boxWidth:14}}}};

function makeBar(id, data, color){
  const top = Object.entries(data).sort((a,b)=>b[1]-a[1]).slice(0,10);
  new Chart(document.getElementById(id), {
    type:'bar',
    data:{labels:top.map(x=>x[0]),
          datasets:[{data:top.map(x=>x[1]),backgroundColor:color,borderRadius:4}]},
    options:{...CHART_OPTS, plugins:{...CHART_OPTS.plugins, legend:{display:false}},
             indexAxis:'y', responsive:true}
  });
}

function makePie(id, data){
  const top = Object.entries(data).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const palette = ['#58a6ff','#3fb950','#f0883e','#f85149','#bc8cff',
                   '#56d364','#ffa657','#79c0ff'];
  new Chart(document.getElementById(id), {
    type:'doughnut',
    data:{labels:top.map(x=>x[0]),
          datasets:[{data:top.map(x=>x[1]),backgroundColor:palette,borderWidth:0}]},
    options:{...PIE_OPTS, responsive:true}
  });
}

const tcpData   = {{ tcp_proto_json|safe }};
const udpData   = {{ udp_proto_json|safe }};
const stateData = {{ states_json|safe }};

if(Object.keys(stateData).length) makePie('chartStates', stateData);
if(Object.keys(tcpData).length)   makeBar('chartTCP', tcpData, '#58a6ff');
if(Object.keys(udpData).length)   makeBar('chartUDP', udpData, '#3fb950');
</script>
</body>
</html>
"""
