# Descripción 

Script en Python para análisis y clasificación automática de logs de red (MikroTik / syslog).

Mi objetivo es organizar grandes volúmenes de logs en categorías claras para facilitar integración, monitoreo de actividad sospechosa, es una de las soluciones para categorizar logs después de sacarlos de extraerlos con syslog-ng

## Objetivo

- Lee logs en tiempo real (tipo `tail -f`)
- Clasifica automáticamente por tipo de tráfico cada uno en su archivo:
    - Firewall
    - DNS
    - DHCP
    - IPsec
    - SNMP
    - Autenticación (login/SSH)
- Identifica logs desconocidos para análisis posterior
- Las reglas de filtrado las separé del script
- Preparado para correr como servicio (`systemd`)

# Script
```python
import time
import os

# CONFIGURACIÓN  -----------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = "/opt/stacks/syslog-ng/syslog-ng/logs/mikrotik.log"
RULES_FILE = os.path.join(SCRIPT_DIR, "rules.txt")
BASE_DIR = "/opt/stacks/syslog-ng/syslog-ng/logs/"

# CARGAR REGLAS DINÁMICAMENTE   -----------------------------------------
def load_rules():
    rules = {}
    current_category = None
    with open(RULES_FILE, "r") as f:
        for line in f:
            line = line.strip().lower()  

	            if not line:.\soporteSystem01#$
                continue  

            if line.startswith("[") and line.endswith("]"):
                current_category = line[1:-1]
                rules[current_category] = []

            else:
                if current_category:
                    rules[current_category].append(line)  
    return rules

  
# CREAR ARCHIVOS POR CATEGORÍA  -----------------------------------------------
    files = {}
    for category in rules.keys():
        path = os.path.join(BASE_DIR, f"{category}.log")
        files[category] = open(path, "a")
    return files


# DETECTAR CATEGORÍA  ----------------------------------------------------
def categorize(line, rules):
    line_lower = line.lower()  

    for category, keywords in rules.items():
        for keyword in keywords:
            if keyword in line_lower:
                return category 

    return "unknown"
  

# MAIN (tipo tail -f)  ----------------------------------------------------
def main():
    rules = load_rules()
    files = init_files(rules)
    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # ir al final del archivo
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue

            category = categorize(line, rules)  

            # guardar en su categoría
            if category in files:
                files[category].write(line)
                files[category].flush()

            else:
                files["unknown"].write(line)
                files["unknown"].flush()  

            # archivo adicional SOLO para revisión manual
            if category == "unknown":
                with open("unknown_review.log", "a") as review:
                    review.write(line) 
  

# EJECUCIÓN  ----------------------------------------------------
if __name__ == "__main__":
    main()
```

# Archivo txt Reglas de Filtrado
```bash
[firewall]
firewall
INPUT-WAN-BLOCK

[dhcp]
dhcp
bootp
ciaddr

[dns]
dns
question:
reply to

[snmp]
snmp
oid >
oid

[ipsec]
ipsec
ike

[tunnel]
l2tp
pptp

[auth]
logged in from
logged out from

[unknown]
```

## Convertir en Servicio
```sh
# Crear servicio systemd
nano /etc/systemd/system/script.service
```

#### Contenido:
```sh
[Unit]  
Description=Analizador de logs MikroTik  
After=network.target  
  
[Service]  
ExecStart=/usr/bin/python3 /opt/ips-monitor/script.py  
Restart=always  
User=logmonitor
WorkingDirectory=/opt/ips-monitor/ 
  
# Evita buffer (para logs en tiempo real)  
Environment=PYTHONUNBUFFERED=1  
  
[Install]  
WantedBy=multi-user.target
```

```python
#  Activar servicio
systemctl daemon-reexec  
systemctl daemon-reload  
systemctl enable script.service
systemctl start script.service
systemctl status script.service

#logs
journalctl -u script -f
```

## Aplicacion de seguridad
```sh
useradd -r -s /usr/sbin/nologin logmonitor                          # Creamos user

# En mi caso tranferi el script a otro lado 
mkdir -p /opt/ips-monitor
mv /root/01_scripts/script.py /opt/ips-monitor/

chown -R logmonitor:logmonitor /opt/ips-monitor                     # asignar dueño a todo el directorio 
chmod -R 550 /opt/ips-monitor                                       # dueño: r-x, grupo: r-x, otros: ---

chown logmonitor:logmonitor /opt/ips-monitor/ips_escaneadas.json
chmod 640 /opt/ips-monitor/ips_escaneadas.json

usermod -aG adm logmonitor                                           # logmonitor entra al grupo de adm para logs

chown -R root:logmonitor /opt/stacks/syslog-ng/syslog-ng/logs/
chmod -R 750 /opt/stacks/syslog-ng/syslog-ng/logs/
sudo -u logmonitor tail -3 /opt/stacks/syslog-ng/syslog-ng/logs/firewall.log  # Test de acceso
```
