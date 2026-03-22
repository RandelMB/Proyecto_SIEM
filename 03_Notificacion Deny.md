# Descripción
En el la sección anterior se trabajo un script para separar logs por lo que es esta ocasión les traigo una forma de notificación con un sistema en Python para monitorear logs de firewall. Analiza IPs, puertos y protocolos, acumula intentos y mantiene historial con persistencia en JSON (evita reprocesar logs).

#### Tecnologías utilizadas:
- Python (procesamiento, parsing, lógica)
- Regex (extracción de datos de logs)
- JSON (persistencia)
- API REST (ipinfo.io para geolocalización)
- Telegram Bot API (interfaz de consulta)
- Linux systemd (automatización y ejecución como servicio)

Se ejecuta como servicio en Linux (systemd) con control de permisos.  
Funciona como un SIEM ligero para análisis y detección de ataques en red.

![[Pasted image 20260322151817.png]]
### Aplicacion de seguridad
```sh
useradd -r -s /usr/sbin/nologin logmonitor                          # Creamos user

# En mi caso tranferi el script a otro lado 
mkdir -p /opt/ips-monitor
mv /root/01_scripts/ips.py /opt/ips-monitor/
touch /opt/ips-monitor/ips_escaneadas.json                          # cree el json requerido para guardar la info

chown -R logmonitor:logmonitor /opt/ips-monitor                     # asignar dueño a todo el directorio 
chmod -R 550 /opt/ips-monitor                                       # dueño: r-x, grupo: r-x, otros: ---
chmod u+w /opt/ips-monitor/ips_escaneadas.json                      # agregarle escritura al usuario 
chmod g+w /opt/ips-monitor/ips_escaneadas.json                      # agregarle escritura al grupo

usermod -aG adm logmonitor                                           # logmonitor entra al grupo de adm para logs

chown -R root:logmonitor /opt/stacks/syslog-ng/syslog-ng/logs/
chmod -R 740 /opt/stacks/syslog-ng/syslog-ng/logs/
sudo -u logmonitor tail -3 /opt/stacks/syslog-ng/syslog-ng/logs/firewall.log  # Test de acceso
```

## Convertir en Servicio
```sh
# Crear servicio systemd
nano /etc/systemd/system/ips.service
```
#### Contenido:
```sh
[Unit]
Description=Monitor de IPs maliciosas (Telegram + Logs)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ips-monitor/ips.py
Restart=always
RestartSec=5
User=logmonitor
WorkingDirectory=/opt/ips-monitor

# Opcional: evita saturaci  n
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
```

```python
#  Activar servicio
systemctl daemon-reexec  
systemctl daemon-reload  
systemctl enable ips.service
systemctl start ips.service
systemctl status ips.service

#logs
journalctl -u ips -f
```

# Script
```python
import time
import re
import requests
import json
import os
from collections import defaultdict
from datetime import datetime  

# CONFIG--------------------------------
LOG_FILE = "/root/logs/deny.log"
STATE_FILE = "ips_escaneadas.json"
BOT_TOKEN = "TU_BOT_TOKEN"
CHAT_ID = "TU_CHAT_ID"
IPINFO_TOKEN = "TU_IPINFO_TOKEN"

log_regex = re.compile(
    r'proto (\w+).*?, (\d+\.\d+\.\d+\.\d+):(\d+)->(\d+\.\d+\.\d+\.\d+):(\d+)'
)  

KEYWORDS = ["BLOCK", "INVALID", "PORTSCAN", "IPSEC-DROP"]  

# DATA-------------------------------------------------
ip_data = defaultdict(lambda: {
    "count": 0,
    "dst_ports": [],
    "protocols": set(),
    "last_seen": "",
    "history": []  # detalle por IP
})  

port_index = defaultdict(list)  # puerto -> [(ip, tipo, fecha)] 
ip_geo_cache = {}
file_offset = 0  

# PERSISTENCIA-----------------------------------------------
def load_state():
    global file_offset  
    if not os.path.exists(STATE_FILE):
        return 
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
    except:
        print("[WARN] JSON corrupto, reiniciando estado")
        return

    for ip, v in data.get("ips", {}).items():
        ip_data[ip]["count"] = v.get("count", 0)
        ip_data[ip]["dst_ports"] = v.get("dst_ports", [])
        ip_data[ip]["protocols"] = set(v.get("protocols", []))
        ip_data[ip]["last_seen"] = v.get("last_seen", "")
        ip_data[ip]["history"] = v.get("history", [])  
    ip_geo_cache.update(data.get("geo", {}))
    file_offset = data.get("offset", 0)

def save_state():
    tmp_file = STATE_FILE + ".tmp"
    data = {
        "ips": ip_data,
        "geo": ip_geo_cache,
        "offset": file_offset
    }

    try:
        with open(tmp_file, "w") as f:
            json.dump(data, f)
        os.replace(tmp_file, STATE_FILE)  # 🔥 reemplazo seguro
    except:
        pass


# GEO----------------------------------------------------
def get_geo(ip):
    if ip in ip_geo_cache:
        return ip_geo_cache[ip]

    try:
        r = requests.get(f"https://ipinfo.io/{ip}?token={IPINFO_TOKEN}", timeout=5)
        d = r.json()
        geo = f"{d.get('country','?')}/{d.get('city','?')}"
    except:
        geo = "Unknown"

    ip_geo_cache[ip] = geo
    return geo

# PARSE LOG--------------------------------------------------------
def process_log():
    global file_offset

    with open(LOG_FILE, "r") as f:
        f.seek(file_offset)

        for line in f:
            if not any(k in line for k in KEYWORDS):
                continue

            match = log_regex.search(line)
            if not match:
                continue

            proto, ip, src_port, _, dst_port = match.groups()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            ip_data[ip]["count"] += 1
            ip_data[ip]["dst_ports"].append(dst_port)
            ip_data[ip]["protocols"].add(proto)
            ip_data[ip]["last_seen"] = now

            # historial
            ip_data[ip]["history"].append({
                "time": now,
                "src": src_port,
                "dst": dst_port
            })

            # index por puerto
            port_index[dst_port].append((ip, "DST", now))
            port_index[src_port].append((ip, "SRC", now))

        file_offset = f.tell()

    save_state()


# FORMATO PUERTOS-----------------------------------------------------
def format_ports(port_list):
    if not port_list:
        return "-"

    last = port_list[-1]
    total = len(set(port_list))

    if total == 1:
        return last

    return f"{last} (+{total-1})"


# REPORTES ----------------------------------------------------------
def report_summary():
    process_log()

    msg = "<b>📊 RESUMEN IPS</b>\n\n<pre>"
    msg += "IP              CNT  DST_PORTS   PROTO   LAST_SEEN       GEO\n"
    msg += "-" * 80 + "\n"

    sorted_ips = sorted(ip_data.items(), key=lambda x: x[1]["count"], reverse=True)

    for ip, d in sorted_ips[:20]:
        ports = format_ports(d["dst_ports"])
        proto = ",".join(d["protocols"])
        geo = get_geo(ip)

        msg += f"{ip:<15} {d['count']:<4} {ports:<11} {proto:<7} {d['last_seen']:<16} {geo}\n"

    msg += "</pre>"
    return msg


def report_ip(ip):
    process_log()

    if ip not in ip_data:
        return "IP no encontrada"

    geo = get_geo(ip)

    msg = f"<b>🔎 DETALLE {ip} ({geo})</b>\n\n<pre>"
    msg += "TIME                SRC_PORT   DST_PORT\n"
    msg += "-" * 50 + "\n"

    for h in ip_data[ip]["history"][-20:]:
        msg += f"{h['time']:<19} {h['src']:<10} {h['dst']}\n"

    msg += "</pre>"
    return msg


def report_port(port):
    process_log()

    msg = f"<b>🔎 PUERTO {port}</b>\n\n<pre>"
    msg += "IP              TYPE   TIME              GEO\n"
    msg += "-" * 70 + "\n"

    for ip, typ, t in port_index.get(port, [])[-20:]:
        geo = get_geo(ip)
        msg += f"{ip:<15} {typ:<6} {t:<17} {geo}\n"

    msg += "</pre>"
    return msg


# TELEGRAM ----------------------------------------------------------
def send(msg):
    requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"}
    )

def get_updates(offset=None):
    r = requests.get(
        f"https://api.telegram.org/bot{BOT_TOKEN}/getUpdates",
        params={"timeout": 30, "offset": offset}
    )
    return r.json()


# BOT ----------------------------------------------------------
def run_bot():
    offset = None

    while True:
        data = get_updates(offset)

        for u in data.get("result", []):
            offset = u["update_id"] + 1

            try:
                text = u["message"]["text"].strip()
                chat_id = str(u["message"]["chat"]["id"])
            except:
                continue

            if chat_id != CHAT_ID:
                continue

            if text.lower() == "ip":
                send(report_summary())

            elif text.lower().startswith("ip "):
                ip = text.split()[1]
                send(report_ip(ip))

            elif text.lower().startswith("port "):
                port = text.split()[1]
                send(report_port(port))

        time.sleep(1)


# MAIN  ----------------------------------------------------------
if __name__ == "__main__":
    load_state()
    run_bot()
```