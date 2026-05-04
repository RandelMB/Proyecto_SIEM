


# OBTENER USUARIO Y PASSWORD (GVMD DOCKER)

```bash
docker ps | grep gvmd                          # identificar contenedor gvmd

docker exec -it <gvmd> gvmd --get-users --verbose   # listar usuarios y roles
docker logs <gvmd> | grep -i password          # buscar password en logs

docker exec -it <gvmd> env | grep -i pass      # buscar variables de entorno
```

# RESET PASSWORD ADMIN

```bash
docker exec -it <gvmd> gvmd --user=admin --new-password='NuevaClaveSegura'   # cambiar password
```

# CREAR USUARIO NUEVO (SI NO EXISTE)

```bash
docker exec -it <gvmd> gvmd --create-user=admin   # crear usuario
docker exec -it <gvmd> gvmd --user=admin --new-password='NuevaClaveSegura'   # asignar password
```

# VERIFICAR ACCESO

```bash
docker exec -it <gvmd> gvmd --get-users        # confirmar usuario existe

docker ps                                      # validar servicios activos
docker logs <gvmd> | tail -n 50                 # revisar errores recientes
```

# DETECTAR NOMBRE AUTOMATICAMENTE

```bash
GVMD=$(docker ps --format '{{.Names}}' | grep -i gvmd)   # detectar nombre
echo $GVMD                                               # validar

docker exec -it $GVMD gvmd --get-users --verbose         # usar variable
```