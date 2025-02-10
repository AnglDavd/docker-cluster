# Docker Swarm Cluster Setup
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Script automatizado para configurar un cluster Docker Swarm con almacenamiento distribuido GlusterFS, gestión mediante Portainer, y características avanzadas de alta disponibilidad.

## Características

- 🐳 Configuración automatizada de Docker Swarm
- 📦 Almacenamiento distribuido con GlusterFS
- 🎛️ Gestión del cluster con Portainer
- 🔄 Alta disponibilidad y redundancia
- 📊 Monitoreo y alertas
- 🔒 Seguridad con TLS y tokens encriptados
- 💾 Backup y restauración
- 🖥️ Soporte para múltiples sistemas operativos
- 🏥 Sistema de salud de datos

## Requisitos

### Sistema Operativo
- Ubuntu (recomendado)
- CentOS/RHEL
- Debian

### Hardware
- CPU: 2 cores mínimo recomendado
- RAM: 4GB mínimo recomendado
- Disco: 10GB mínimo para el sistema
- Red: Conectividad entre todos los nodos

### Software
- bash
- curl
- openssl
- bc
- netstat
- ping

### Puertos Requeridos
- 2377/tcp: Docker Swarm cluster management
- 7946/tcp+udp: Container network discovery
- 4789/udp: Overlay network traffic
- 8000/tcp: Portainer HTTP
- 9443/tcp: Portainer HTTPS
- 24007/tcp: GlusterFS Daemon
- 24008/tcp: GlusterFS Management
- 49152-49251/tcp: GlusterFS Bricks

## Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/usuario/docker-cluster.git
cd docker-cluster
```

2. Hacer el script ejecutable:
```bash
chmod +x docker-cluster.sh
```

## Uso

### Crear Nuevo Cluster

```bash
./docker-cluster.sh --master 192.168.1.10 \
                   --nodes 192.168.1.11,192.168.1.12 \
                   --cluster nuevo \
                   --role manager
```

### Unir Nodo al Cluster

```bash
./docker-cluster.sh --master 192.168.1.10 \
                   --cluster unir \
                   --role worker \
                   --token <token>
```

### Agregar Nodos al Cluster

```bash
./docker-cluster.sh --master 192.168.1.10 \
                   --nodes 192.168.1.13,192.168.1.14 \
                   --cluster agregar
```

## Configuración

### Variables de Entorno

| Variable | Descripción | Valor por Defecto |
|----------|-------------|-------------------|
| DOCKER_CLUSTER_CONFIG | Ruta al archivo de configuración | /etc/docker-cluster/config |
| DOCKER_CLUSTER_DEBUG | Habilitar modo debug | false |
| DOCKER_CLUSTER_PORTAINER_HTTP_PORT | Puerto HTTP de Portainer | 8000 |
| DOCKER_CLUSTER_PORTAINER_HTTPS_PORT | Puerto HTTPS de Portainer | 9443 |
| DOCKER_CLUSTER_MONITOR_ALERT_MAIL | Email para alertas | "" |

Ver [documentación completa](docs/configuration.md) para más variables.

### Archivo de Configuración

Crear `/etc/docker-cluster/config`:

```bash
# Configuración de Puertos
PORTAINER_HTTP_PORT=8000
PORTAINER_HTTPS_PORT=9443

# Configuración de Monitoreo
MONITOR_ALERT_DISK=80
MONITOR_ALERT_CPU=90
MONITOR_ALERT_MEM=85
MONITOR_ALERT_MAIL="admin@example.com"

# Configuración de Rendimiento
GLUSTER_PERF_LEVEL="high"
GLUSTER_CACHE_SIZE=512

# Configuración de Salud de Datos
HEALTH_CHECK_INTERVAL=300    # Intervalo de chequeo en segundos
HEALTH_AUTO_HEAL=true       # Reparación automática
HEALTH_REPLICA_COUNT=3      # Número de réplicas
HEALTH_SNAPSHOT_INTERVAL=3600  # Intervalo de snapshots
HEALTH_SNAPSHOT_RETAIN=24   # Snapshots a retener
HEALTH_SCRUB_INTERVAL=604800  # Intervalo de scrubbing
HEALTH_QUOTA_ENABLED=true   # Habilitar cuotas
HEALTH_QUOTA_SOFT=85        # Límite soft (%)
HEALTH_QUOTA_HARD=95        # Límite hard (%)
```

## Monitoreo

El script incluye un sistema de monitoreo que recolecta:

- Estadísticas de Docker
- Uso de sistema (CPU, memoria, disco)
- Estado de GlusterFS
- Estado del cluster Swarm
- Estadísticas de red

### Alertas

Se generan alertas cuando:

- Uso de disco > 80%
- Uso de CPU > 90%
- Uso de memoria > 85%
- Servicios críticos caídos

Las alertas se pueden enviar por email configurando `MONITOR_ALERT_MAIL`.

## Salud de Datos

El sistema implementa un conjunto completo de características para garantizar la integridad y disponibilidad de los datos:

### Monitoreo de Salud

- Verificación continua del estado del volumen
- Detección de bricks offline
- Identificación de split-brain
- Monitoreo de cuotas de espacio
- Alertas configurables

### Reparación Automática

- Self-healing automático
- Reparación de split-brain
- Recuperación de bricks caídos
- Verificación post-reparación

### Snapshots Automáticos

- Creación periódica configurable
- Rotación automática
- Retención configurable
- Restauración simplificada

### Mantenimiento Preventivo

- Scrubbing periódico del volumen
- Limpieza de datos corruptos
- Verificación de integridad
- Optimización automática

### Gestión de Cuotas

- Límites soft y hard configurables
- Alertas de uso de espacio
- Prevención de desbordamiento
- Monitoreo por directorio

### Comandos de Mantenimiento

```bash
# Verificar salud del volumen
./docker-cluster.sh --health-check

# Forzar reparación
./docker-cluster.sh --repair-volume

# Crear snapshot manual
./docker-cluster.sh --create-snapshot

# Iniciar scrubbing
./docker-cluster.sh --scrub-volume

# Ver estado de cuotas
./docker-cluster.sh --quota-status
```

### Logs de Salud

```bash
# Ver logs de salud
tail -f /var/log/docker-cluster/health.log

# Ver estado de reparaciones
gluster volume heal gluster-volume info

# Ver snapshots
gluster snapshot list
```

## Seguridad

### Certificados TLS

- Generación automática de CA
- Certificados por nodo
- Rotación automática
- Permisos restrictivos

### Tokens

- Encriptación de tokens
- Almacenamiento seguro
- Permisos restrictivos

## Backup y Restauración

### Backup Automático

- Configuración de Docker
- Certificados TLS
- Tokens del cluster
- Logs del sistema

### Restauración

```bash
# Restaurar desde el último backup
./docker-cluster.sh --restore latest

# Restaurar desde backup específico
./docker-cluster.sh --restore /var/backups/docker-cluster/20250101_120000
```

## Troubleshooting

### Logs

- Archivo principal: `/var/log/docker-cluster.log`
- Métricas: `/var/lib/docker-cluster/monitor/metrics/`
- Alertas: `/var/lib/docker-cluster/monitor/alerts/`
- Salud: `/var/log/docker-cluster/health.log`

### Modo Debug

```bash
export DOCKER_CLUSTER_DEBUG=true
./docker-cluster.sh [opciones]
```

## Contribuir

1. Fork el repositorio
2. Crear rama feature (`git checkout -b feature/nombre`)
3. Commit cambios (`git commit -am 'Agregar característica'`)
4. Push a la rama (`git push origin feature/nombre`)
5. Crear Pull Request

## Licencia

Este proyecto está bajo la licencia MIT. Ver [LICENSE](LICENSE) para más detalles.

## Autores

- Cline - *Trabajo inicial* - [GitHub](https://github.com/usuario)

## Agradecimientos

- Comunidad Docker
- Comunidad GlusterFS
- Equipo Portainer
