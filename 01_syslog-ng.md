
### Introducción

Este proyecto tiene como objetivo centralizar, organizar y analizar los logs generados por un router **MikroTik RouterOS**. Los registros serán enviados mediante Syslog hacia un servidor que ejecuta **syslog-ng** dentro de un contenedor **Docker**.

Posteriormente, estos registros serán procesados con scripts desarrollados en **Python**, aplicando técnicas de filtrado, análisis automatizado e inteligencia artificial para identificar patrones, detectar eventos relevantes y facilitar el análisis de la actividad de la red.

### Se crea el actions en Mikrotik
![[Pasted image 20260322160642.png]]

### Compose.yml
```d
services:
  syslog:
    image: balabit/syslog-ng
    container_name: syslog
    restart: always
    ports:
      - "514:514/udp"
    volumes:
      - /opt/syslog-ng:/etc/syslog-ng
      - /var/log/syslog-ng:/var/log/syslog-ng
```

### Acrchivo "syslog-ng.conf"
```python
@version: 4.10
@include "scl.conf"

# -------SOURCE --------
source s_mikrotik {
    udp(ip(198.26.30.1) port(514));
};

# ------DESTINATIONS -------
destination d_local_mikrotik {
    file(
      "/var/log/syslog-ng/mikrotik.log"
      create-dirs(yes)
      owner("root")
      group("adm")
      perm(0640)
    );
};

# ------LOG PATH---------#

log {
    source(s_mikrotik);
    destination(d_local_mikrotik);
};
```

### Troubleshooting
```c
# Accede al contenedor
docker exec -it syslog-ng bash

# Validar el Uso de los puertos( Tanto fuera como dentro del contenedor )
ss -lunp | grep 514
ss -lunp | grep 151
```










