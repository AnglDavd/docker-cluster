#!/bin/bash
###############################################################################
# Docker Swarm Cluster Setup Script
# ================================
#
# DESCRIPCIÓN:
#   Este script automatiza la configuración de un cluster Docker Swarm con
#   almacenamiento distribuido usando GlusterFS, gestión mediante Portainer,
#   y características de alta disponibilidad y redundancia.
#
# CARACTERÍSTICAS:
#   - Configuración automatizada de Docker Swarm
#   - Almacenamiento distribuido con GlusterFS
#   - Gestión del cluster con Portainer
#   - Alta disponibilidad y redundancia
#   - Monitoreo y alertas
#   - Seguridad con TLS y tokens encriptados
#   - Backup y restauración
#   - Soporte para múltiples sistemas operativos
#
# REQUISITOS:
#   - Sistema operativo: Ubuntu (recomendado), CentOS/RHEL, o Debian
#   - Espacio en disco: Mínimo 10GB
#   - RAM: 4GB mínimo recomendado
#   - CPU: 2 cores mínimo recomendado
#   - Red: Conectividad entre todos los nodos
#   - Puertos: Ver documentación de puertos requeridos
#
# USO:
#   ./docker-cluster.sh --master <IP> --nodes <IP1,IP2,...> --cluster <modo> --role <rol>
#
# OPCIONES:
#   --master, -m    IP del nodo primario
#   --nodes, -n     Lista de IPs de otros nodos (separadas por comas)
#   --cluster, -c   Modo del cluster (nuevo, unir, agregar)
#   --role, -r      Rol del nodo (manager, worker)
#   --token, -t     Token para unirse al cluster
#
# EJEMPLOS:
#   1. Crear nuevo cluster:
#      ./docker-cluster.sh --master 192.168.1.10 --nodes 192.168.1.11,192.168.1.12 --cluster nuevo --role manager
#
#   2. Unir nodo al cluster:
#      ./docker-cluster.sh --master 192.168.1.10 --cluster unir --role worker --token <token>
#
#   3. Agregar nodos al cluster:
#      ./docker-cluster.sh --master 192.168.1.10 --nodes 192.168.1.13,192.168.1.14 --cluster agregar
#
# VARIABLES DE ENTORNO:
#   DOCKER_CLUSTER_CONFIG    Ruta al archivo de configuración
#   DOCKER_CLUSTER_DEBUG     Habilitar modo debug (true/false)
#   Ver documentación completa para más variables
#
# AUTOR:
#   Cline
#
# VERSIÓN:
#   1.3
#
# LICENCIA:
#   MIT License
#
# NOTAS:
#   - Se recomienda revisar la documentación completa antes de usar
#   - Hacer backup antes de ejecutar en producción
#   - Verificar requisitos de sistema y red
#   - Configurar firewall según necesidades
#
###############################################################################

set -eo pipefail

# Funciones de Configuración
# -------------------------

# load_config: Carga la configuración desde un archivo externo
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
# Efectos: Modifica variables globales de CONFIG
load_config() {
    local config_file=${DOCKER_CLUSTER_CONFIG:-/etc/docker-cluster/config}
    if [[ -f "$config_file" ]]; then
        debug "Cargando configuración desde $config_file"
        source "$config_file"
    fi
}

# load_env: Carga configuración desde variables de entorno
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
# Efectos: Modifica variables globales de CONFIG según variables de entorno
load_env() {
    # Mapeo de variables de entorno a configuración
    local -A env_map=(
        [DOCKER_CLUSTER_PORTAINER_HTTP_PORT]="PORTAINER_HTTP_PORT"
        [DOCKER_CLUSTER_PORTAINER_HTTPS_PORT]="PORTAINER_HTTPS_PORT"
        [DOCKER_CLUSTER_ESPACIO_REQUERIDO]="ESPACIO_REQUERIDO"
        [DOCKER_CLUSTER_VOLUMEN_GLS]="VOLUMEN_GLS"
        [DOCKER_CLUSTER_LOG_FILE]="LOG_FILE"
        [DOCKER_CLUSTER_LOG_MAX_SIZE]="LOG_MAX_SIZE"
        [DOCKER_CLUSTER_LOG_ROTATE_COUNT]="LOG_ROTATE_COUNT"
        [DOCKER_CLUSTER_SHARED_PATH]="SHARED_PATH"
        [DOCKER_CLUSTER_BRICK_PATH]="BRICK_PATH"
        [DOCKER_CLUSTER_GLUSTER_MIN_VERSION]="GLUSTER_MIN_VERSION"
        [DOCKER_CLUSTER_TOKEN_DIR]="TOKEN_DIR"
        [DOCKER_CLUSTER_DEBUG]="DEBUG"
        [DOCKER_CLUSTER_PING_TIMEOUT]="PING_TIMEOUT"
        [DOCKER_CLUSTER_PING_COUNT]="PING_COUNT"
        [DOCKER_CLUSTER_PORT_TIMEOUT]="PORT_TIMEOUT"
        [DOCKER_CLUSTER_MTU_MIN]="MTU_MIN"
        [DOCKER_CLUSTER_CERT_DIR]="CERT_DIR"
        [DOCKER_CLUSTER_CERT_EXPIRY]="CERT_EXPIRY"
        [DOCKER_CLUSTER_CERT_BITS]="CERT_BITS"
        [DOCKER_CLUSTER_CERT_COUNTRY]="CERT_COUNTRY"
        [DOCKER_CLUSTER_CERT_STATE]="CERT_STATE"
        [DOCKER_CLUSTER_CERT_ORG]="CERT_ORG"
        [DOCKER_CLUSTER_BACKUP_DIR]="BACKUP_DIR"
        [DOCKER_CLUSTER_CLEANUP_TIMEOUT]="CLEANUP_TIMEOUT"
        [DOCKER_CLUSTER_GLUSTER_CACHE_SIZE]="GLUSTER_CACHE_SIZE"
        [DOCKER_CLUSTER_GLUSTER_IO_THREADS]="GLUSTER_IO_THREADS"
        [DOCKER_CLUSTER_GLUSTER_WRITE_BEHIND]="GLUSTER_WRITE_BEHIND"
        [DOCKER_CLUSTER_GLUSTER_READ_AHEAD]="GLUSTER_READ_AHEAD"
        [DOCKER_CLUSTER_GLUSTER_PING_TIMEOUT]="GLUSTER_PING_TIMEOUT"
        [DOCKER_CLUSTER_GLUSTER_STAT_PREFETCH]="GLUSTER_STAT_PREFETCH"
        [DOCKER_CLUSTER_GLUSTER_PERF_LEVEL]="GLUSTER_PERF_LEVEL"
    )
    
    # Procesar variables de entorno
    for env_var in "${!env_map[@]}"; do
        if [[ -n "${!env_var}" ]]; then
            debug "Configurando ${env_map[$env_var]} desde variable de entorno $env_var"
            CONFIG[${env_map[$env_var]}]="${!env_var}"
        fi
    done
}

# validate_config: Valida la configuración cargada
# Argumentos: Ninguno
# Retorna: 0 si válida, error() si inválida
# Efectos: Termina el script si la configuración es inválida
validate_config() {
    local required_configs=(
        "PORTAINER_HTTP_PORT"
        "PORTAINER_HTTPS_PORT"
        "ESPACIO_REQUERIDO"
        "VOLUMEN_GLS"
        "LOG_FILE"
        "SHARED_PATH"
        "BRICK_PATH"
        "GLUSTER_MIN_VERSION"
        "TOKEN_DIR"
    )
    
    for config in "${required_configs[@]}"; do
        if [[ -z "${CONFIG[$config]}" ]]; then
            error "Configuración requerida no encontrada: $config"
        fi
    done
    
    # Validar valores numéricos
    [[ "${CONFIG[PORTAINER_HTTP_PORT]}" =~ ^[0-9]+$ ]] || error "Puerto HTTP inválido"
    [[ "${CONFIG[PORTAINER_HTTPS_PORT]}" =~ ^[0-9]+$ ]] || error "Puerto HTTPS inválido"
    [[ "${CONFIG[ESPACIO_REQUERIDO]}" =~ ^[0-9]+$ ]] || error "Espacio requerido inválido"
    
    # Validar rutas
    [[ -d "$(dirname "${CONFIG[LOG_FILE]}")" ]] || error "Directorio de logs no existe"
    [[ -d "$(dirname "${CONFIG[SHARED_PATH]}")" ]] || error "Directorio compartido no existe"
    
    # Validar nivel de rendimiento
    case "${CONFIG[GLUSTER_PERF_LEVEL]}" in
        low|medium|high) ;;
        *) error "Nivel de rendimiento inválido: ${CONFIG[GLUSTER_PERF_LEVEL]}" ;;
    esac
}

# Configuración Global
declare -A CONFIG=(
    [PORTAINER_HTTP_PORT]=8000
    [PORTAINER_HTTPS_PORT]=9443
    [ESPACIO_REQUERIDO]=10
    [VOLUMEN_GLS]="gluster-volume"
    [LOG_FILE]="/var/log/docker-cluster.log"
    [LOG_MAX_SIZE]=10485760  # 10MB en bytes
    [LOG_ROTATE_COUNT]=7     # Número de archivos de respaldo
    [SHARED_PATH]="/mnt/docker-shared"
    [BRICK_PATH]="/data/gluster/brick1"
    [GLUSTER_MIN_VERSION]="7.0"
    [TOKEN_DIR]="/etc/docker/swarm"
    [DEBUG]="false"          # Habilitar/deshabilitar mensajes de debug
    [PING_TIMEOUT]=2         # Timeout para ping en segundos
    [PING_COUNT]=3           # Número de intentos de ping
    [PORT_TIMEOUT]=5         # Timeout para verificación de puertos en segundos
    [MTU_MIN]=1400          # MTU mínimo requerido
    [CERT_DIR]="/etc/docker/certs"  # Directorio para certificados TLS
    [CERT_EXPIRY]=365       # Validez de certificados en días
    [CERT_BITS]=4096        # Tamaño de clave RSA
    [CERT_COUNTRY]="ES"     # País para certificados
    [CERT_STATE]="Madrid"   # Estado/Provincia para certificados
    [CERT_ORG]="Docker Swarm Cluster"  # Organización para certificados
    [BACKUP_DIR]="/var/backups/docker-cluster"  # Directorio para backups
    [CLEANUP_TIMEOUT]=300   # Timeout para limpieza en segundos
    [GLUSTER_CACHE_SIZE]=512      # Tamaño de cache en MB
    [GLUSTER_IO_THREADS]=32       # Número de threads de I/O
    [GLUSTER_WRITE_BEHIND]=8      # Tamaño de write-behind en MB
    [GLUSTER_READ_AHEAD]=16       # Tamaño de read-ahead en MB
    [GLUSTER_PING_TIMEOUT]=10     # Timeout de ping en segundos
    [GLUSTER_STAT_PREFETCH]=1     # Habilitar prefetch de metadatos
    [GLUSTER_PERF_LEVEL]="high"   # Nivel de rendimiento (low/medium/high)
    [MONITOR_INTERVAL]=60         # Intervalo de monitoreo en segundos
    [MONITOR_DIR]="/var/lib/docker-cluster/monitor"  # Directorio para métricas
    [MONITOR_RETENTION]=30        # Retención de métricas en días
    [MONITOR_ALERT_DISK]=80      # Alerta de uso de disco (%)
    [MONITOR_ALERT_CPU]=90       # Alerta de uso de CPU (%)
    [MONITOR_ALERT_MEM]=85       # Alerta de uso de memoria (%)
    [MONITOR_ALERT_MAIL]=""      # Email para alertas
    [HEALTH_CHECK_INTERVAL]=300  # Intervalo de chequeo de salud en segundos
    [HEALTH_AUTO_HEAL]=true     # Reparación automática de volúmenes
    [HEALTH_REPLICA_COUNT]=3     # Número de réplicas para datos críticos
    [HEALTH_SNAPSHOT_INTERVAL]=3600  # Intervalo de snapshots en segundos
    [HEALTH_SNAPSHOT_RETAIN]=24  # Número de snapshots a retener
    [HEALTH_SCRUB_INTERVAL]=604800  # Intervalo de scrubbing en segundos (7 días)
    [HEALTH_QUOTA_ENABLED]=true  # Habilitar cuotas de volumen
    [HEALTH_QUOTA_SOFT]=85       # Límite soft de cuota (%)
    [HEALTH_QUOTA_HARD]=95       # Límite hard de cuota (%)
)

# Variables de estado para rollback
declare -a ROLLBACK_ACTIONS=()

# Variables de Estado
NODO_PRIMARIO=""
OTROS_NODOS=""
ES_PRIMARIO=false
MODO_CLUSTER="nuevo"
ROL_NODO="manager"
TOKEN_MANAGER=""
TOKEN_WORKER=""

# Configuración de Logging
setup_logging() {
    # Crear directorio de logs si no existe
    local log_dir=$(dirname "${CONFIG[LOG_FILE]}")
    mkdir -p "$log_dir"
    chmod 750 "$log_dir"
    
    # Configurar rotación de logs
    cat > /etc/logrotate.d/docker-cluster << EOF
${CONFIG[LOG_FILE]} {
    daily
    rotate ${CONFIG[LOG_ROTATE_COUNT]}
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    size ${CONFIG[LOG_MAX_SIZE]}
}
EOF
    
    # Forzar rotación inicial si el archivo es muy grande
    if [[ -f "${CONFIG[LOG_FILE]}" && $(stat -f%z "${CONFIG[LOG_FILE]}") -gt ${CONFIG[LOG_MAX_SIZE]} ]]; then
        logrotate -f /etc/logrotate.d/docker-cluster
    fi
    
    # Establecer permisos del archivo de log
    touch "${CONFIG[LOG_FILE]}"
    chmod 640 "${CONFIG[LOG_FILE]}"
    chown root:root "${CONFIG[LOG_FILE]}"
}

# Funciones de Logging
# -------------------

# log: Registra un mensaje en el archivo de log y lo muestra en pantalla
# Argumentos:
#   $1 - Nivel de log (INFO, WARN, ERROR, DEBUG)
#   $2 - Mensaje a registrar
# Retorna: 0 si éxito
# Efectos: Escribe en archivo de log y stdout
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local script_name=$(basename "$0")
    local line_num=${BASH_LINENO[0]}
    local func_name="${FUNCNAME[1]:-main}"
    local log_message="[$timestamp][$level][$script_name:$func_name:$line_num] $message"
    
    echo "$log_message" | tee -a "${CONFIG[LOG_FILE]}"
    
    # Registrar en syslog eventos críticos
    if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
        logger -t docker-cluster "$log_message"
    fi
}

# Wrappers de logging
info() { log "INFO" "$1"; }
warn() { log "WARN" "$1"; }
error() { log "ERROR" "$1"; exit 1; }
debug() { [[ "${CONFIG[DEBUG]}" == "true" ]] && log "DEBUG" "$1"; }

# Detectar Sistema Operativo
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        OS=$(uname -s)
        VERSION=$(uname -r)
    fi
    info "Sistema Operativo detectado: $OS $VERSION"
}

# Configurar comandos según OS
setup_os_commands() {
    case "$OS" in
        *"Ubuntu"*)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="$PKG_MANAGER update"
            PKG_INSTALL="$PKG_MANAGER install -y"
            GLUSTER_REPO_CMD="curl -fsSL https://download.gluster.org/pub/gluster/glusterfs/10/rsa.pub | apt-key add - && echo deb [arch=amd64] https://download.gluster.org/pub/gluster/glusterfs/10/LATEST/Ubuntu/$(lsb_release -cs)/amd64/apt $(lsb_release -cs) main > /etc/apt/sources.list.d/gluster.list"
            FIREWALL_CMD="ufw"
            ;;
        *"Debian"*)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="$PKG_MANAGER update"
            PKG_INSTALL="$PKG_MANAGER install -y"
            GLUSTER_REPO_CMD="curl -fsSL https://download.gluster.org/pub/gluster/glusterfs/10/rsa.pub | apt-key add - && echo deb [arch=amd64] https://download.gluster.org/pub/gluster/glusterfs/10/LATEST/Debian/$(lsb_release -cs)/amd64/apt $(lsb_release -cs) main > /etc/apt/sources.list.d/gluster.list"
            FIREWALL_CMD="ufw"
            ;;
        *"CentOS"*|*"Red Hat"*)
            PKG_MANAGER="yum"
            PKG_UPDATE="$PKG_MANAGER makecache"
            PKG_INSTALL="$PKG_MANAGER install -y"
            GLUSTER_REPO_CMD="yum install -y centos-release-gluster"
            FIREWALL_CMD="firewall-cmd"
            ;;
        *)
            error "Sistema operativo no soportado: $OS"
            ;;
    esac
}

# Verificar dependencias requeridas
check_dependencies() {
    local deps=(bc netstat curl ping openssl ntpdate sysstat iotop mail)
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep >/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        warn "Dependencias faltantes: ${missing_deps[*]}"
        if [[ "$OS" == *"Ubuntu"* || "$OS" == *"Debian"* ]]; then
            install_packages "${missing_deps[@]}"
        elif [[ "$OS" == *"CentOS"* || "$OS" == *"Red Hat"* ]]; then
            # Mapeo de nombres de paquetes para CentOS/RHEL
            local pkg_map=(
                [ntpdate]=chrony
                [mail]=mailx
            )
            local to_install=()
            for dep in "${missing_deps[@]}"; do
                to_install+=(${pkg_map[$dep]:-$dep})
            done
            install_packages "${to_install[@]}"
        fi
    fi
    
    info "Todas las dependencias están instaladas"
}

# Funciones de Red
# ---------------

# check_port_availability: Verifica si un puerto está disponible
# Argumentos:
#   $1 - Número de puerto a verificar
# Retorna: 0 si disponible, error() si en uso
# Efectos: Ninguno
check_port_availability() {
    local port=$1
    ! netstat -tuln | grep -q ":$port " || error "Puerto $port en uso"
}

check_port_connectivity() {
    local host=$1
    local port=$2
    local proto=${3:-tcp}
    local timeout=${CONFIG[PORT_TIMEOUT]}
    
    debug "Verificando conectividad $proto al puerto $port en $host"
    if ! timeout $timeout bash -c "echo > /dev/$proto/$host/$port" 2>/dev/null; then
        error "No hay conectividad $proto al puerto $port en $host"
    fi
}

check_mtu() {
    local interface=$1
    local min_mtu=${CONFIG[MTU_MIN]}
    local current_mtu=$(ip link show $interface | grep -oP 'mtu \K\d+')
    
    debug "MTU actual en $interface: $current_mtu"
    if [[ $current_mtu -lt $min_mtu ]]; then
        warn "MTU en $interface ($current_mtu) es menor que el mínimo recomendado ($min_mtu)"
        warn "Esto podría afectar el rendimiento de la red overlay"
    fi
}

get_default_interface() {
    local default_route=$(ip route | grep '^default' | head -n1)
    echo $default_route | awk '{print $5}'
}

check_connectivity() {
    local host=$1
    local count=${CONFIG[PING_COUNT]}
    local timeout=${CONFIG[PING_TIMEOUT]}
    local success=0
    
    debug "Verificando conectividad básica con $host"
    for ((i=1; i<=count; i++)); do
        if ping -c 1 -W $timeout $host &>/dev/null; then
            ((success++))
        fi
    done
    
    if [[ $success -eq 0 ]]; then
        error "Sin conectividad con $host después de $count intentos"
    elif [[ $success -lt $count ]]; then
        warn "Conectividad inestable con $host ($success/$count paquetes recibidos)"
    fi
    
    # Verificar MTU en la interfaz por defecto
    local default_interface=$(get_default_interface)
    check_mtu $default_interface
}

# Funciones de Limpieza y Rollback
# -------------------------------

# register_rollback: Registra una acción de rollback para ejecutar en caso de error
# Argumentos:
#   $1 - Comando de rollback a ejecutar
# Retorna: 0 si éxito
# Efectos: Agrega comando a ROLLBACK_ACTIONS
register_rollback() {
    local action=$1
    ROLLBACK_ACTIONS+=("$action")
    debug "Registrada acción de rollback: $action"
}

execute_rollback() {
    warn "Iniciando rollback..."
    
    # Ejecutar acciones de rollback en orden inverso
    for ((i=${#ROLLBACK_ACTIONS[@]}-1; i>=0; i--)); do
        local action=${ROLLBACK_ACTIONS[i]}
        debug "Ejecutando rollback: $action"
        eval "$action" || warn "Error en rollback: $action"
    done
    
    ROLLBACK_ACTIONS=()
    info "Rollback completado"
}

cleanup() {
    local exit_code=$?
    
    if [[ $exit_code -ne 0 ]]; then
        warn "Script terminado con error (código $exit_code)"
        execute_rollback
    fi
    
    # Limpiar archivos temporales
    find /tmp -name "docker-cluster-*" -type f -mmin +60 -delete 2>/dev/null
    
    # Rotar logs si es necesario
    if [[ -f "${CONFIG[LOG_FILE]}" ]]; then
        logrotate -f /etc/logrotate.d/docker-cluster 2>/dev/null
    fi
    
    exit $exit_code
}

backup_config() {
    local backup_dir="${CONFIG[BACKUP_DIR]}/$(date +%Y%m%d_%H%M%S)"
    debug "Creando backup en $backup_dir"
    
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    
    # Backup de configuración Docker
    if [[ -d /etc/docker ]]; then
        tar czf "$backup_dir/docker-config.tar.gz" /etc/docker
    fi
    
    # Backup de certificados
    if [[ -d "${CONFIG[CERT_DIR]}" ]]; then
        tar czf "$backup_dir/certs.tar.gz" "${CONFIG[CERT_DIR]}"
    fi
    
    # Backup de tokens
    if [[ -d "${CONFIG[TOKEN_DIR]}" ]]; then
        tar czf "$backup_dir/tokens.tar.gz" "${CONFIG[TOKEN_DIR]}"
    fi
    
    # Backup de logs
    if [[ -f "${CONFIG[LOG_FILE]}" ]]; then
        cp "${CONFIG[LOG_FILE]}" "$backup_dir/docker-cluster.log"
    fi
    
    info "Backup creado en $backup_dir"
}

restore_backup() {
    local backup_dir=$1
    [[ -d "$backup_dir" ]] || error "Directorio de backup no encontrado: $backup_dir"
    
    debug "Restaurando backup desde $backup_dir"
    
    # Restaurar configuración Docker
    if [[ -f "$backup_dir/docker-config.tar.gz" ]]; then
        tar xzf "$backup_dir/docker-config.tar.gz" -C /
    fi
    
    # Restaurar certificados
    if [[ -f "$backup_dir/certs.tar.gz" ]]; then
        tar xzf "$backup_dir/certs.tar.gz" -C /
    fi
    
    # Restaurar tokens
    if [[ -f "$backup_dir/tokens.tar.gz" ]]; then
        tar xzf "$backup_dir/tokens.tar.gz" -C /
    fi
    
    info "Backup restaurado desde $backup_dir"
}

# Funciones de Utilidad y Validación
# ---------------------------------

# Validar dirección IP
validate_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        error "IP inválida: $ip"
    fi
    for octet in $(echo "$ip" | tr '.' ' '); do
        if [[ $octet -lt 0 || $octet -gt 255 ]]; then
            error "Octeto inválido en IP: $octet"
        fi
    done
}

# Verificar espacio disponible
check_available_space() {
    local path=$1
    local min_space=$2
    local reserve_space=2  # GB de espacio reservado
    
    # Verificar si el path existe
    if [[ ! -d "$path" ]]; then
        mkdir -p "$path" || error "No se puede crear el directorio $path"
    fi
    
    # Obtener espacio disponible
    local available=$(df -BG "$path" | awk 'NR==2 {print $4}' | sed 's/G//')
    local total=$(df -BG "$path" | awk 'NR==2 {print $2}' | sed 's/G//')
    local used=$(df -BG "$path" | awk 'NR==2 {print $3}' | sed 's/G//')
    
    debug "Espacio en $path - Total: ${total}GB, Usado: ${used}GB, Disponible: ${available}GB"
    
    # Verificar espacio mínimo
    if [[ $available -lt $((min_space + reserve_space)) ]]; then
        warn "Espacio insuficiente en $path (disponible: ${available}GB, requerido: $((min_space + reserve_space))GB)"
        return 1
    fi
    
    # Verificar fragmentación
    local fragmentation=$(df -h "$path" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $fragmentation -gt 80 ]]; then
        warn "Alta fragmentación en $path: $fragmentation%"
    fi
    
    return 0
}

# Verificar y rotar logs
rotate_logs() {
    local log_file=$1
    local max_size=${2:-${CONFIG[LOG_MAX_SIZE]}}
    local max_files=${3:-${CONFIG[LOG_ROTATE_COUNT]}}
    local compress=${4:-true}
    
    # Verificar si el archivo existe
    [[ -f "$log_file" ]] || return 0
    
    # Obtener tamaño actual
    local current_size=$(stat -f%z "$log_file" 2>/dev/null || echo 0)
    
    if [[ $current_size -gt $max_size ]]; then
        debug "Rotando log $log_file"
        
        # Eliminar logs antiguos si se excede el límite
        local log_count=$(ls -1 "$log_file"* 2>/dev/null | wc -l)
        if [[ $log_count -ge $max_files ]]; then
            local oldest_log=$(ls -t "$log_file"* | tail -n1)
            rm -f "$oldest_log"
        fi
        
        # Rotar log
        local timestamp=$(date +%Y%m%d_%H%M%S)
        mv "$log_file" "$log_file.$timestamp"
        
        # Comprimir log rotado
        if [[ "$compress" == "true" ]]; then
            gzip -9 "$log_file.$timestamp" &
        fi
        
        # Crear nuevo archivo
        touch "$log_file"
        chmod 640 "$log_file"
        
        # Verificar espacio en disco
        if ! check_available_space "$(dirname "$log_file")" 1; then
            warn "Espacio bajo en disco para logs"
            find "$(dirname "$log_file")" -name "$(basename "$log_file")*" -mtime +7 -delete
        fi
    fi
}

# Verificar certificados
check_cert_expiry() {
    local cert="${CONFIG[CERT_DIR]}/node.crt"
    [[ ! -f "$cert" ]] && return 0
    
    local expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
    local exp_date=$(date -d "$expiry" +%s)
    local now=$(date +%s)
    local days_left=$(( ($exp_date - $now) / 86400 ))
    
    if [[ $days_left -lt 30 ]]; then
        warn "Certificado expira en $days_left días"
        if [[ $days_left -lt 7 ]]; then
            setup_certificates
        fi
    fi
}

# Verificar y corregir permisos
verify_permissions() {
    local dir=$1
    local expected_perm=$2
    local actual_perm=$(stat -c %a "$dir")
    if [[ "$actual_perm" != "$expected_perm" ]]; then
        warn "Corrigiendo permisos en $dir"
        chmod "$expected_perm" "$dir"
    fi
}

# Verificar sincronización de tiempo
check_time_sync() {
    command -v ntpdate >/dev/null || return 0
    
    local max_drift=5
    local nodes=($OTROS_NODOS)
    for node in "${nodes[@]}"; do
        local drift=$(ntpdate -q "$node" 2>/dev/null | awk '/offset/ {print $6}')
        if [[ -n "$drift" && ${drift#-} -gt $max_drift ]]; then
            warn "Deriva de tiempo excesiva con $node: $drift segundos"
        fi
    done
}

# Verificar módulos de seguridad
check_security_modules() {
    if command -v getenforce &>/dev/null; then
        if [[ $(getenforce) == "Enforcing" ]]; then
            warn "SELinux está en modo Enforcing"
            warn "Algunos contenedores podrían requerir ajustes de contexto"
        fi
    fi
    
    if [[ -x /usr/sbin/aa-status ]]; then
        if aa-status --enabled 2>/dev/null; then
            warn "AppArmor está activo"
            warn "Algunos contenedores podrían requerir perfiles personalizados"
        fi
    fi
}

# Generar y verificar checksums
generate_checksum() {
    local dir=$1
    find "$dir" -type f ! -name "checksums.sha256" -exec sha256sum {} \; > "$dir/checksums.sha256"
}

verify_checksum() {
    local dir=$1
    if [[ -f "$dir/checksums.sha256" ]]; then
        cd "$dir" && sha256sum -c checksums.sha256 2>/dev/null
        return $?
    fi
    return 1
}

# Funciones base
check_root() { [[ $EUID -eq 0 ]] || error "Este script debe ejecutarse como root"; }
check_service() { 
    timeout 10 systemctl is-active --quiet "$1" || error "Servicio $1 inactivo"
}

# Manejo de señales y recuperación
trap 'handle_signal SIGHUP' SIGHUP
trap 'handle_signal SIGINT' SIGINT
trap 'handle_signal SIGTERM' SIGTERM
trap 'handle_signal EXIT' EXIT
trap 'handle_error $? ${LINENO} "$BASH_COMMAND"' ERR

# Manejar señales del sistema
handle_signal() {
    local signal=$1
    
    case $signal in
        SIGHUP)
            info "Recibida señal SIGHUP, recargando configuración..."
            if reload_config; then
                info "Configuración recargada exitosamente"
            else
                warn "Error al recargar configuración"
            fi
            ;;
        SIGINT|SIGTERM)
            info "Recibida señal $signal, iniciando apagado graceful..."
            graceful_shutdown
            ;;
        EXIT)
            cleanup
            ;;
    esac
}

# Recargar configuración
reload_config() {
    # Guardar configuración actual
    local old_config=$(declare -p CONFIG)
    
    # Intentar cargar nueva configuración
    if ! load_config || ! load_env || ! validate_config; then
        # Restaurar configuración anterior en caso de error
        eval "$old_config"
        return 1
    fi
    
    # Aplicar cambios que requieren reinicio
    if config_requires_restart; then
        warn "Algunos cambios requieren reinicio de servicios"
        restart_services
    fi
    
    return 0
}

# Verificar si los cambios requieren reinicio
config_requires_restart() {
    local restart_params=(
        PORTAINER_HTTP_PORT
        PORTAINER_HTTPS_PORT
        GLUSTER_CACHE_SIZE
        GLUSTER_IO_THREADS
    )
    
    for param in "${restart_params[@]}"; do
        if [[ "${CONFIG[$param]}" != "${OLD_CONFIG[$param]}" ]]; then
            return 0
        fi
    done
    
    return 1
}

# Reiniciar servicios afectados
restart_services() {
    # Reiniciar servicios en orden correcto
    for service in glusterd docker portainer; do
        if systemctl is-active --quiet $service; then
            systemctl restart $service
        fi
    done
}

# Apagado graceful del sistema
graceful_shutdown() {
    info "Iniciando apagado graceful del sistema..."
    
    # Crear snapshot final si es necesario
    if [[ "${CONFIG[HEALTH_AUTO_HEAL]}" == "true" ]]; then
        create_snapshot || warn "Error al crear snapshot final"
    fi
    
    # Detener servicios en orden
    systemctl stop docker-cluster-monitor
    systemctl stop gluster-health-monitor
    
    # Detener contenedores gracefully
    if [[ "$ES_PRIMARIO" == "true" ]]; then
        docker service scale portainer=0
    fi
    
    # Esperar a que los contenedores se detengan
    local timeout=30
    while [[ $timeout -gt 0 && $(docker ps -q | wc -l) -gt 0 ]]; do
        sleep 1
        ((timeout--))
    done
    
    # Desmontar volúmenes
    if mountpoint -q "${CONFIG[SHARED_PATH]}"; then
        umount "${CONFIG[SHARED_PATH]}"
    fi
    
    # Detener servicios base
    systemctl stop docker
    systemctl stop glusterd
    
    info "Apagado graceful completado"
    exit 0
}

# Funciones de seguridad para tokens
encrypt_token() {
    local token=$1
    echo "$token" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"${NODO_PRIMARIO}" 2>/dev/null | base64
}

decrypt_token() {
    local token_file=$1
    if [[ -f "$token_file" ]]; then
        base64 -d "$token_file" | openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"${NODO_PRIMARIO}" 2>/dev/null
    else
        error "Archivo de token no encontrado: $token_file"
    fi
}

# Configurar firewall según OS
configure_firewall() {
    local ports=("$@")
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            for port in "${ports[@]}"; do
                ufw allow $port
            done
            ufw reload
            ;;
        *"CentOS"*|*"Red Hat"*)
            for port in "${ports[@]}"; do
                firewall-cmd --permanent --add-port=$port
            done
            firewall-cmd --reload
            ;;
    esac
    info "Firewall configurado con puertos: ${ports[*]}"
}

# Instalar paquetes según OS
install_packages() {
    local packages=("$@")
    debug "Actualizando repositorios"
    $PKG_UPDATE
    debug "Instalando paquetes: ${packages[*]}"
    $PKG_INSTALL "${packages[@]}"
}

# Configurar grupos de usuarios
setup_user_groups() {
    # Crear grupo docker si no existe
    if ! getent group docker >/dev/null; then
        debug "Creando grupo docker"
        groupadd docker
    fi
    
    # Crear grupo gluster si no existe
    if ! getent group gluster >/dev/null; then
        debug "Creando grupo gluster"
        groupadd gluster
    fi
    
    # Agregar usuario actual a los grupos
    local current_user=$(who am i | awk '{print $1}')
    if [ -n "$current_user" ]; then
        usermod -aG docker $current_user
        usermod -aG gluster $current_user
        info "Usuario $current_user agregado a grupos docker y gluster"
    fi
}

# Instalar Docker según OS
install_docker() {
    if ! command -v docker &>/dev/null; then
        info "Instalando Docker..."
        setup_user_groups
        case "$OS" in
            *"Ubuntu"*)
                install_packages apt-transport-https ca-certificates curl software-properties-common
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
                chmod a+r /etc/apt/keyrings/docker.asc
                
                echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
                $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null
                
                $PKG_UPDATE
                install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
            *"Debian"*)
                install_packages apt-transport-https ca-certificates curl gnupg
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
                chmod a+r /etc/apt/keyrings/docker.asc
                
                echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
                $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null
                
                $PKG_UPDATE
                install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
            *"CentOS"*|*"Red Hat"*)
                install_packages yum-utils
                yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                ;;
        esac
        
        # Configurar Docker para usar systemd como cgroup driver
        debug "Configurando daemon.json"
        mkdir -p /etc/docker
        cat > /etc/docker/daemon.json << EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
EOF
        
        # Reiniciar y habilitar Docker
        debug "Habilitando y reiniciando servicio Docker"
        systemctl enable docker
        systemctl daemon-reload
        systemctl restart docker
    fi

    # Verificar instalación
    docker version || error "Error en la instalación de Docker"
    docker info || error "Error en la configuración de Docker"
    
    info "Docker instalado y configurado exitosamente"
}

# Instalar GlusterFS según OS
install_glusterfs() {
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            install_packages gnupg2 software-properties-common
            eval "$GLUSTER_REPO_CMD"
            $PKG_UPDATE
            install_packages glusterfs-server glusterfs-client
            
            # Verificar instalación
            if ! systemctl is-active --quiet glusterd; then
                debug "Iniciando servicio glusterd"
                systemctl start glusterd
                systemctl enable glusterd
            fi
            ;;
        *"CentOS"*|*"Red Hat"*)
            eval "$GLUSTER_REPO_CMD"
            install_packages glusterfs-server glusterfs-client
            
            # Verificar instalación
            if ! systemctl is-active --quiet glusterd; then
                debug "Iniciando servicio glusterd"
                systemctl start glusterd
                systemctl enable glusterd
            fi
            ;;
    esac
    
    # Verificar versión instalada
    local version=$(glusterfs --version | head -n1 | grep -oP '\d+\.\d+')
    info "GlusterFS versión $version instalado exitosamente"
}

# Verificaciones del Sistema
check_disk_space() {
    # Verificar espacio en /
    local root_available=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
    debug "Espacio disponible en /: ${root_available}GB"
    [[ $root_available -ge ${CONFIG[ESPACIO_REQUERIDO]} ]] || 
        error "Espacio insuficiente en /. Se requieren ${CONFIG[ESPACIO_REQUERIDO]}GB, hay ${root_available}GB"
    
    # Verificar espacio en disco para GlusterFS
    local gluster_disk=$(check_disk_for_gluster)
    local gluster_size=$(lsblk -b $gluster_disk | awk 'NR==2 {print $4}')
    local gluster_size_gb=$((gluster_size/1024/1024/1024))
    debug "Espacio disponible en $gluster_disk: ${gluster_size_gb}GB"
    
    [[ $gluster_size_gb -ge $((${CONFIG[ESPACIO_REQUERIDO]} * 2)) ]] ||
        error "Espacio insuficiente en $gluster_disk. Se requieren $((${CONFIG[ESPACIO_REQUERIDO]} * 2))GB, hay ${gluster_size_gb}GB"
    
    info "Verificación de espacio completada: OK"
}

check_disk_for_gluster() {
    local disk=$(lsblk -nd -o NAME | grep -m1 "sd[a-z]")
    [[ -n "$disk" ]] || error "No se encontró disco para GlusterFS"
    debug "Disco seleccionado para GlusterFS: /dev/$disk"
    echo "/dev/$disk"
}

verify_ports() {
    local required_ports=(
        # Puerto:Protocolo
        "2377:tcp"   # Docker Swarm cluster management
        "7946:tcp"   # Container network discovery
        "7946:udp"   # Container network discovery
        "4789:udp"   # Overlay network traffic
        "${CONFIG[PORTAINER_HTTP_PORT]}:tcp"
        "${CONFIG[PORTAINER_HTTPS_PORT]}:tcp"
        "24007:tcp"  # GlusterFS Daemon
        "24008:tcp"  # GlusterFS Management
        "49152:tcp"  # GlusterFS Bricks start
    )
    
    debug "Verificando disponibilidad de puertos locales"
    for port_proto in "${required_ports[@]}"; do
        local port=${port_proto%:*}
        check_port_availability "$port"
    done
    
    if [[ -n "$NODO_PRIMARIO" && "$NODO_PRIMARIO" != "$(hostname -I | awk '{print $1}')" ]]; then
        debug "Verificando conectividad de puertos con nodo primario"
        for port_proto in "${required_ports[@]}"; do
            local port=${port_proto%:*}
            local proto=${port_proto#*:}
            check_port_connectivity "$NODO_PRIMARIO" "$port" "$proto"
        done
    fi
    
    if [[ -n "$OTROS_NODOS" ]]; then
        debug "Verificando conectividad de puertos con otros nodos"
        IFS=',' read -ra NODOS <<< "$OTROS_NODOS"
        for nodo in "${NODOS[@]}"; do
            for port_proto in "${required_ports[@]}"; do
                local port=${port_proto%:*}
                local proto=${port_proto#*:}
                check_port_connectivity "$nodo" "$port" "$proto"
            done
        done
    fi
    
    info "Verificación de puertos completada exitosamente"
}

# Validación de argumentos
validate_args() {
    # Validar nodo primario
    [[ -n "$NODO_PRIMARIO" ]] || error "Debe especificar --master"
    validate_ip "$NODO_PRIMARIO"
    
    # Validar modo del cluster
    case $MODO_CLUSTER in
        nuevo)
            [[ -n "$OTROS_NODOS" ]] || error "Modo nuevo requiere --nodes"
            # Validar y verificar nodos adicionales
            IFS=',' read -ra NODOS <<< "$OTROS_NODOS"
            [[ ${#NODOS[@]} -ge 2 ]] || error "Se requieren al menos 2 nodos adicionales"
            for nodo in "${NODOS[@]}"; do
                validate_ip "$nodo"
                [[ "$nodo" != "$NODO_PRIMARIO" ]] || error "Nodo $nodo duplicado"
                debug "Verificando conectividad con $nodo"
                if ! check_connectivity "$nodo"; then
                    error "Sin conectividad con nodo $nodo"
                fi
            done
            ;;
        unir)
            # Validar token
            if [[ "$ROL_NODO" == "manager" ]]; then
                [[ -n "$TOKEN_MANAGER" ]] || error "Modo unir como manager requiere token de manager"
            else
                [[ -n "$TOKEN_WORKER" ]] || error "Modo unir como worker requiere token de worker"
            fi
            # Verificar conectividad con nodo primario
            debug "Verificando conectividad con nodo primario"
            if ! check_connectivity "$NODO_PRIMARIO"; then
                error "Sin conectividad con nodo primario $NODO_PRIMARIO"
            fi
            ;;
        agregar)
            # Validar permisos y nodos
            [[ "$ES_PRIMARIO" == true ]] || error "Solo el nodo primario puede agregar nodos"
            [[ -n "$OTROS_NODOS" ]] || error "Modo agregar requiere --nodes"
            
            # Validar y verificar nuevos nodos
            IFS=',' read -ra NODOS <<< "$OTROS_NODOS"
            for nodo in "${NODOS[@]}"; do
                validate_ip "$nodo"
                [[ "$nodo" != "$NODO_PRIMARIO" ]] || error "Nodo $nodo duplicado"
                # Verificar si el nodo ya existe en el cluster
                if docker node ls 2>/dev/null | grep -q "$nodo"; then
                    error "El nodo $nodo ya existe en el cluster"
                fi
                debug "Verificando conectividad con $nodo"
                if ! check_connectivity "$nodo"; then
                    error "Sin conectividad con nodo $nodo"
                fi
            done
            ;;
        *)
            error "Modo inválido: $MODO_CLUSTER (use: nuevo, unir, agregar)"
            ;;
    esac
    
    # Validar rol del nodo
    case "$ROL_NODO" in
        manager|worker) ;;
        *) error "Rol inválido: $ROL_NODO (use: manager, worker)" ;;
    esac
    
    # Validar combinaciones de rol y modo
    if [[ "$MODO_CLUSTER" == "nuevo" && "$ROL_NODO" == "worker" ]]; then
        error "El primer nodo debe ser manager"
    fi
    
    # Verificar recursos del sistema
    check_system_resources
    
    info "Validación de argumentos completada"
}

# Verificar recursos del sistema
check_system_resources() {
    # Verificar CPU
    local cpu_cores=$(nproc)
    if [[ $cpu_cores -lt 2 ]]; then
        warn "Se recomienda al menos 2 cores de CPU (actual: $cpu_cores)"
    fi
    
    # Verificar memoria
    local mem_total=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $mem_total -lt 4 ]]; then
        warn "Se recomienda al menos 4GB de RAM (actual: ${mem_total}GB)"
    fi
    
    # Verificar espacio en disco
    check_disk_space
    
    # Verificar límites del sistema
    check_system_limits
    
    # Verificar resolución DNS
    check_dns_resolution
}

# Verificar límites del sistema
check_system_limits() {
    local required_limits=(
        "fs.file-max=524288"
        "fs.inotify.max_user_instances=512"
        "fs.inotify.max_user_watches=524288"
    )
    
    for limit in "${required_limits[@]}"; do
        local key=${limit%=*}
        local value=${limit#*=}
        local current=$(sysctl -n "$key")
        
        if [[ $current -lt $value ]]; then
            warn "Límite del sistema bajo para $key: $current (recomendado: $value)"
            echo "$limit" >> /etc/sysctl.d/99-docker-cluster.conf
        fi
    done
    
    sysctl -p /etc/sysctl.d/99-docker-cluster.conf
}

# Verificar resolución DNS
check_dns_resolution() {
    local dns_servers=(
        "8.8.8.8"
        "8.8.4.4"
    )
    
    for server in "${dns_servers[@]}"; do
        if ! ping -c 1 -W 2 "$server" &>/dev/null; then
            warn "No se puede alcanzar el servidor DNS $server"
        fi
    done
    
    # Verificar resolución inversa
    local hostname=$(hostname -f)
    if ! host "$hostname" &>/dev/null; then
        warn "No se puede resolver el hostname $hostname"
    fi
}

# Configuración del Sistema
setup_directories() {
    local dirs=("$@")
    for dir in "${dirs[@]}"; do
        debug "Creando directorio: $dir"
        mkdir -p "$dir" || error "No se pudo crear $dir"
    done
    info "Directorios creados exitosamente"
}

# Optimización de GlusterFS
optimize_glusterfs() {
    local perf_level=${CONFIG[GLUSTER_PERF_LEVEL]}
    debug "Optimizando GlusterFS para nivel de rendimiento: $perf_level"
    
    # Configurar sysctl para rendimiento
    cat > /etc/sysctl.d/99-glusterfs.conf << EOF
vm.dirty_ratio = 40
vm.dirty_background_ratio = 5
vm.swappiness = 10
net.core.rmem_max = 56623104
net.core.wmem_max = 56623104
EOF
    sysctl -p /etc/sysctl.d/99-glusterfs.conf
    
    # Configurar opciones de rendimiento según nivel
    case $perf_level in
        high)
            local cache_size=${CONFIG[GLUSTER_CACHE_SIZE]}
            local io_threads=${CONFIG[GLUSTER_IO_THREADS]}
            local write_behind=${CONFIG[GLUSTER_WRITE_BEHIND]}
            local read_ahead=${CONFIG[GLUSTER_READ_AHEAD]}
            ;;
        medium)
            local cache_size=$((${CONFIG[GLUSTER_CACHE_SIZE]}/2))
            local io_threads=$((${CONFIG[GLUSTER_IO_THREADS]}/2))
            local write_behind=$((${CONFIG[GLUSTER_WRITE_BEHIND]}/2))
            local read_ahead=$((${CONFIG[GLUSTER_READ_AHEAD]}/2))
            ;;
        low)
            local cache_size=$((${CONFIG[GLUSTER_CACHE_SIZE]}/4))
            local io_threads=$((${CONFIG[GLUSTER_IO_THREADS]}/4))
            local write_behind=$((${CONFIG[GLUSTER_WRITE_BEHIND]}/4))
            local read_ahead=$((${CONFIG[GLUSTER_READ_AHEAD]}/4))
            ;;
    esac
    
    # Configurar opciones en glusterd.vol
    cat > /etc/glusterfs/glusterd.vol << EOF
volume management
    type mgmt/glusterd
    option working-directory /var/lib/glusterd
    option transport-type socket
    option transport.socket.keepalive-time ${CONFIG[GLUSTER_PING_TIMEOUT]}
    option transport.socket.keepalive-interval 2
    option transport.socket.read-fail-log false
    option max-port 49151
    option event-threads $io_threads
    option base-port 49152
end-volume
EOF
    
    systemctl restart glusterd
    info "Configuración base de GlusterFS optimizada"
}

setup_glusterfs() {
    # Instalar si es necesario
    if ! command -v glusterfs &>/dev/null; then
        install_glusterfs
    fi
    
    # Verificar versión
    local version=$(glusterfs --version | head -n1 | grep -oP '\d+\.\d+')
    [[ $(echo "$version < ${CONFIG[GLUSTER_MIN_VERSION]}" | bc -l) -eq 1 ]] &&
        error "Se requiere GlusterFS ${CONFIG[GLUSTER_MIN_VERSION]} o superior"
    
    # Optimizar configuración
    optimize_glusterfs

    # Preparar disco para GlusterFS
    local disk_path=$(check_disk_for_gluster)
    if ! mountpoint -q ${CONFIG[BRICK_PATH]}; then
        debug "Formateando disco $disk_path"
        mkfs.xfs -f $disk_path
        echo "$disk_path ${CONFIG[BRICK_PATH]} xfs defaults 0 0" >> /etc/fstab
        mount ${CONFIG[BRICK_PATH]}
    fi

    # Configurar firewall
    local ports=(
        24007/tcp  # GlusterFS Daemon
        24008/tcp  # GlusterFS Management
        49152-49251/tcp  # GlusterFS Bricks
        2377/tcp  # Docker Swarm
        7946/{tcp,udp}  # Docker Swarm discovery
        4789/udp  # Docker overlay network
        ${CONFIG[PORTAINER_HTTP_PORT]}/tcp
        ${CONFIG[PORTAINER_HTTPS_PORT]}/tcp
    )
    configure_firewall "${ports[@]}"
}

# Funciones de Salud de Datos
# -------------------------

# check_volume_health: Verifica la salud del volumen GlusterFS
# Argumentos: Ninguno
# Retorna: 0 si saludable, 1 si necesita reparación
check_volume_health() {
    local volume=${CONFIG[VOLUMEN_GLS]}
    local issues=0
    
    debug "Verificando salud del volumen $volume"
    
    # Verificar estado del volumen
    if ! gluster volume status $volume | grep -q "Status: Started"; then
        warn "Volumen $volume no está iniciado"
        ((issues++))
    fi
    
    # Verificar bricks
    if ! gluster volume status $volume | grep -q "Online"; then
        warn "Bricks offline detectados en $volume"
        ((issues++))
    fi
    
    # Verificar split-brain
    if gluster volume heal $volume info | grep -q "Split-brain"; then
        warn "Split-brain detectado en $volume"
        ((issues++))
    fi
    
    # Verificar cuotas si están habilitadas
    if [[ "${CONFIG[HEALTH_QUOTA_ENABLED]}" == "true" ]]; then
        local usage=$(df -h ${CONFIG[SHARED_PATH]} | awk 'NR==2 {print $5}' | sed 's/%//')
        if [[ $usage -ge ${CONFIG[HEALTH_QUOTA_HARD]} ]]; then
            error "Cuota hard excedida en $volume: $usage%"
        elif [[ $usage -ge ${CONFIG[HEALTH_QUOTA_SOFT]} ]]; then
            warn "Cuota soft excedida en $volume: $usage%"
            ((issues++))
        fi
    fi
    
    return $issues
}

# heal_volume: Repara problemas en el volumen
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
heal_volume() {
    local volume=${CONFIG[VOLUMEN_GLS]}
    debug "Iniciando reparación del volumen $volume"
    
    # Forzar un self-heal
    gluster volume heal $volume full
    
    # Esperar a que termine el healing
    local timeout=300
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if ! gluster volume heal $volume info | grep -q "Number of entries:"; then
            info "Reparación de $volume completada"
            return 0
        fi
        sleep 5
        ((elapsed+=5))
    done
    
    warn "Timeout en reparación de $volume"
    return 1
}

# create_snapshot: Crea un snapshot del volumen
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
create_snapshot() {
    local volume=${CONFIG[VOLUMEN_GLS]}
    local snapshot_name="${volume}_$(date +%Y%m%d_%H%M%S)"
    
    debug "Creando snapshot $snapshot_name"
    
    # Crear snapshot
    if ! gluster snapshot create $snapshot_name $volume; then
        warn "Error al crear snapshot $snapshot_name"
        return 1
    fi
    
    # Rotar snapshots antiguos
    local snapshots=($(gluster snapshot list | sort))
    local count=${#snapshots[@]}
    local max_retain=${CONFIG[HEALTH_SNAPSHOT_RETAIN]}
    
    if [[ $count -gt $max_retain ]]; then
        local to_delete=$((count - max_retain))
        for ((i=0; i<to_delete; i++)); do
            debug "Eliminando snapshot antiguo ${snapshots[i]}"
            gluster snapshot delete ${snapshots[i]}
        done
    fi
    
    return 0
}

# scrub_volume: Realiza limpieza profunda del volumen
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
scrub_volume() {
    local volume=${CONFIG[VOLUMEN_GLS]}
    debug "Iniciando scrubbing de $volume"
    
    # Verificar si el scrubbing ya está en progreso
    if gluster volume status $volume | grep -q "scrubbing in progress"; then
        debug "Scrubbing ya en progreso en $volume"
        return 0
    fi
    
    # Iniciar scrubbing
    if ! gluster volume scrub $volume start; then
        warn "Error al iniciar scrubbing en $volume"
        return 1
    fi
    
    info "Scrubbing iniciado en $volume"
    return 0
}

setup_gluster_volume() {
    local peers=($@)
    local replica_count=${CONFIG[HEALTH_REPLICA_COUNT]}
    
    # Verificar número mínimo de nodos para replicación
    if [[ $((${#peers[@]}+1)) -lt $replica_count ]]; then
        error "Se requieren al menos $replica_count nodos para replicación"
    fi
    
    # Crear volumen
    debug "Creando volumen GlusterFS con $replica_count réplicas"
    local cmd="gluster volume create ${CONFIG[VOLUMEN_GLS]} replica $replica_count transport tcp ${CONFIG[BRICK_PATH]}"
    for peer in "${peers[@]}"; do
        cmd="$cmd $peer:${CONFIG[BRICK_PATH]}"
    done
    
    eval "$cmd force" || error "Error creando volumen GlusterFS"
    
    # Configurar opciones avanzadas del volumen
    debug "Configurando opciones avanzadas del volumen"
    local perf_opts=(
        "network.ping-timeout=${CONFIG[GLUSTER_PING_TIMEOUT]}"
        "performance.cache-size=${CONFIG[GLUSTER_CACHE_SIZE]}MB"
        "performance.io-thread-count=${CONFIG[GLUSTER_IO_THREADS]}"
        "performance.write-behind-window-size=${CONFIG[GLUSTER_WRITE_BEHIND]}MB"
        "performance.read-ahead-page-count=$((${CONFIG[GLUSTER_READ_AHEAD]}*256))"
        "performance.quick-read=on"
        "performance.stat-prefetch=${CONFIG[GLUSTER_STAT_PREFETCH]}"
        "performance.low-prio-threads=$((${CONFIG[GLUSTER_IO_THREADS]}/4))"
        "performance.client-io-threads=on"
        "network.remote-dio=enable"
        "cluster.lookup-optimize=on"
        "cluster.read-hash-mode=2"
    )
    
    for opt in "${perf_opts[@]}"; do
        gluster volume set ${CONFIG[VOLUMEN_GLS]} ${opt}
    done
    
    gluster volume start ${CONFIG[VOLUMEN_GLS]}
    info "Volumen GlusterFS creado y configurado exitosamente"
}

# Gestión de certificados TLS
setup_certificates() {
    local cert_dir="${CONFIG[CERT_DIR]}"
    debug "Configurando certificados TLS en $cert_dir"
    
    # Crear directorio de certificados
    mkdir -p "$cert_dir"
    chmod 700 "$cert_dir"
    
    # Generar CA privada si no existe
    if [[ ! -f "$cert_dir/ca.key" ]]; then
        debug "Generando CA privada"
        openssl genrsa -out "$cert_dir/ca.key" ${CONFIG[CERT_BITS]}
        chmod 400 "$cert_dir/ca.key"
        
        # Generar certificado CA
        openssl req -new -x509 -days ${CONFIG[CERT_EXPIRY]} \
            -key "$cert_dir/ca.key" \
            -out "$cert_dir/ca.crt" \
            -subj "/C=${CONFIG[CERT_COUNTRY]}/ST=${CONFIG[CERT_STATE]}/O=${CONFIG[CERT_ORG]}/CN=swarm-ca"
    fi
    
    # Generar certificado para el nodo si no existe
    if [[ ! -f "$cert_dir/node.key" ]]; then
        debug "Generando certificado para el nodo"
        openssl genrsa -out "$cert_dir/node.key" ${CONFIG[CERT_BITS]}
        chmod 400 "$cert_dir/node.key"
        
        # Generar CSR
        openssl req -new \
            -key "$cert_dir/node.key" \
            -out "$cert_dir/node.csr" \
            -subj "/C=${CONFIG[CERT_COUNTRY]}/ST=${CONFIG[CERT_STATE]}/O=${CONFIG[CERT_ORG]}/CN=$NODO_PRIMARIO"
        
        # Firmar certificado
        openssl x509 -req -days ${CONFIG[CERT_EXPIRY]} \
            -in "$cert_dir/node.csr" \
            -CA "$cert_dir/ca.crt" \
            -CAkey "$cert_dir/ca.key" \
            -CAcreateserial \
            -out "$cert_dir/node.crt"
        
        rm -f "$cert_dir/node.csr"
    fi
    
    # Configurar Docker para usar TLS
    debug "Configurando Docker para usar TLS"
    cat > /etc/docker/daemon.json << EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "tls": true,
  "tlscacert": "$cert_dir/ca.crt",
  "tlscert": "$cert_dir/node.crt",
  "tlskey": "$cert_dir/node.key",
  "tlsverify": true
}
EOF
    
    systemctl restart docker
    info "Certificados TLS configurados exitosamente"
}

setup_swarm() {
    # Configurar certificados TLS
    setup_certificates
    
    # Inicializar Swarm con TLS
    debug "Inicializando Docker Swarm con TLS"
    docker swarm init --advertise-addr $NODO_PRIMARIO \
        --external-ca protocol=cfssl,url=https://$NODO_PRIMARIO:${CONFIG[PORTAINER_HTTPS_PORT]}
    
    # Configurar red overlay
    debug "Creando red overlay"
    if ! docker network create \
        --driver overlay \
        --attachable \
        --subnet=10.0.0.0/16 \
        --gateway=10.0.0.1 \
        --opt encrypted \
        cluster-net; then
        error "Error al crear la red overlay cluster-net"
    fi
    info "Red overlay cluster-net creada exitosamente"
    
    # Configurar directorio de tokens
    debug "Configurando directorio de tokens"
    mkdir -p "${CONFIG[TOKEN_DIR]}"
    chmod 700 "${CONFIG[TOKEN_DIR]}"
    
    # Encriptar y guardar tokens
    debug "Encriptando y guardando tokens"
    encrypt_token "$(docker swarm join-token manager -q)" > "${CONFIG[TOKEN_DIR]}/manager_token.enc"
    encrypt_token "$(docker swarm join-token worker -q)" > "${CONFIG[TOKEN_DIR]}/worker_token.enc"
    
    # Establecer permisos restrictivos
    chown -R root:root "${CONFIG[TOKEN_DIR]}"
    chmod 400 "${CONFIG[TOKEN_DIR]}"/*
    
    info "Tokens encriptados y guardados con permisos restrictivos"
    
    # Crear volumen para Portainer
    create_docker_volume portainer_data
    
    # Instalar Portainer
    debug "Instalando Portainer"
    if ! docker service create \
        --name portainer \
        --network cluster-net \
        --publish ${CONFIG[PORTAINER_HTTP_PORT]}:8000 \
        --publish ${CONFIG[PORTAINER_HTTPS_PORT]}:9443 \
        --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
        --mount type=volume,src=portainer_data,dst=/data \
        --constraint 'node.role == manager' \
        --replicas 1 \
        portainer/portainer-ce:latest; then
        error "Error al crear el servicio Portainer"
    fi
    info "Servicio Portainer creado exitosamente"
}

create_docker_volume() {
    local name=$1
    local path="${CONFIG[SHARED_PATH]}/volumes/$name"
    
    debug "Creando volumen Docker: $name"
    mkdir -p "$path"
    chmod 755 "$path"
    
    if ! docker volume create \
        --driver local \
        --opt type=none \
        --opt o=bind \
        --opt device="$path" \
        "$name"; then
        error "Error al crear el volumen Docker $name"
    fi
    info "Volumen Docker $name creado exitosamente"
}

# Funciones de Monitoreo
# --------------------

# setup_monitoring: Configura el sistema de monitoreo y alertas
# Argumentos: Ninguno
# Retorna: 0 si éxito, error() si falla
# Efectos:
#   - Crea directorios de monitoreo
#   - Instala herramientas de monitoreo
#   - Configura servicio systemd
#   - Inicia recolección de métricas
# setup_volume_health: Configura monitoreo de salud del volumen
# Argumentos: Ninguno
# Retorna: 0 si éxito, 1 si error
setup_volume_health() {
    local volume=${CONFIG[VOLUMEN_GLS]}
    debug "Configurando monitoreo de salud para $volume"
    
    # Habilitar cuotas si está configurado
    if [[ "${CONFIG[HEALTH_QUOTA_ENABLED]}" == "true" ]]; then
        gluster volume quota $volume enable
        gluster volume quota $volume limit-usage / ${CONFIG[HEALTH_QUOTA_HARD]}%
        info "Cuotas configuradas para $volume"
    fi
    
    # Crear servicio de monitoreo de salud
    cat > /etc/systemd/system/gluster-health-monitor.service << EOF
[Unit]
Description=GlusterFS Health Monitor
After=glusterd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/gluster-health-monitor
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    # Crear script de monitoreo de salud
    cat > /usr/local/bin/gluster-health-monitor << 'EOF'
#!/bin/bash

HEALTH_CHECK_INTERVAL="${CONFIG[HEALTH_CHECK_INTERVAL]}"
HEALTH_AUTO_HEAL="${CONFIG[HEALTH_AUTO_HEAL]}"
HEALTH_SNAPSHOT_INTERVAL="${CONFIG[HEALTH_SNAPSHOT_INTERVAL]}"
HEALTH_SCRUB_INTERVAL="${CONFIG[HEALTH_SCRUB_INTERVAL]}"
VOLUME="${CONFIG[VOLUMEN_GLS]}"

last_snapshot=0
last_scrub=0

while true; do
    # Verificar salud del volumen
    if ! check_volume_health; then
        if [[ "$HEALTH_AUTO_HEAL" == "true" ]]; then
            heal_volume
        fi
    fi
    
    # Crear snapshot si es tiempo
    current_time=$(date +%s)
    if [[ $((current_time - last_snapshot)) -ge $HEALTH_SNAPSHOT_INTERVAL ]]; then
        if create_snapshot; then
            last_snapshot=$current_time
        fi
    fi
    
    # Realizar scrubbing si es tiempo
    if [[ $((current_time - last_scrub)) -ge $HEALTH_SCRUB_INTERVAL ]]; then
        if scrub_volume; then
            last_scrub=$current_time
        fi
    fi
    
    sleep $HEALTH_CHECK_INTERVAL
done
EOF
    
    chmod +x /usr/local/bin/gluster-health-monitor
    systemctl daemon-reload
    systemctl enable gluster-health-monitor
    systemctl start gluster-health-monitor
    
    info "Monitor de salud configurado exitosamente"
    return 0
}

setup_monitoring() {
    debug "Configurando sistema de monitoreo"
    
    # Configurar monitoreo de salud del volumen
    setup_volume_health
    
    # Crear directorio para métricas
    mkdir -p "${CONFIG[MONITOR_DIR]}"/{metrics,alerts}
    chmod 750 "${CONFIG[MONITOR_DIR]}"
    
    # Configurar retención de métricas
    cat > /etc/logrotate.d/docker-cluster-metrics << EOF
${CONFIG[MONITOR_DIR]}/metrics/*.log {
    daily
    rotate ${CONFIG[MONITOR_RETENTION]}
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    
    # Instalar herramientas de monitoreo
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            install_packages sysstat iotop
            ;;
        *"CentOS"*|*"Red Hat"*)
            install_packages sysstat iotop
            ;;
    esac
    
    # Crear servicio de monitoreo
    cat > /etc/systemd/system/docker-cluster-monitor.service << EOF
[Unit]
Description=Docker Cluster Monitoring Service
After=docker.service

[Service]
Type=simple
ExecStart=/usr/local/bin/docker-cluster-monitor
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    # Crear script de monitoreo
    cat > /usr/local/bin/docker-cluster-monitor << 'EOF'
#!/bin/bash

MONITOR_DIR="${CONFIG[MONITOR_DIR]}"
INTERVAL="${CONFIG[MONITOR_INTERVAL]}"

while true; do
    timestamp=$(date '+%Y%m%d_%H%M%S')
    metrics_file="$MONITOR_DIR/metrics/metrics_$timestamp.log"
    
    # Recolectar métricas
    {
        echo "=== Docker Stats ==="
        docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
        
        echo -e "\n=== System Stats ==="
        top -bn1 | head -n 5
        
        echo -e "\n=== Disk Usage ==="
        df -h
        
        echo -e "\n=== GlusterFS Status ==="
        gluster volume status
        
        echo -e "\n=== Swarm Status ==="
        docker node ls
        
        echo -e "\n=== Network Stats ==="
        netstat -s | head -n 20
    } > "$metrics_file"
    
    # Verificar alertas
    check_alerts
    
    sleep $INTERVAL
done
EOF
    
    chmod +x /usr/local/bin/docker-cluster-monitor
    systemctl daemon-reload
    systemctl enable docker-cluster-monitor
    systemctl start docker-cluster-monitor
    
    info "Sistema de monitoreo configurado exitosamente"
}

check_alerts() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local alert_file="${CONFIG[MONITOR_DIR]}/alerts/alerts_$(date '+%Y%m%d').log"
    local alert_triggered=false
    
    # Verificar uso de disco
    local disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -ge ${CONFIG[MONITOR_ALERT_DISK]} ]]; then
        echo "[$timestamp] ALERT: Disk usage at $disk_usage%" >> "$alert_file"
        alert_triggered=true
    fi
    
    # Verificar uso de CPU
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d. -f1)
    if [[ $cpu_usage -ge ${CONFIG[MONITOR_ALERT_CPU]} ]]; then
        echo "[$timestamp] ALERT: CPU usage at $cpu_usage%" >> "$alert_file"
        alert_triggered=true
    fi
    
    # Verificar uso de memoria
    local mem_usage=$(free | grep Mem | awk '{print $3/$2 * 100}' | cut -d. -f1)
    if [[ $mem_usage -ge ${CONFIG[MONITOR_ALERT_MEM]} ]]; then
        echo "[$timestamp] ALERT: Memory usage at $mem_usage%" >> "$alert_file"
        alert_triggered=true
    fi
    
    # Verificar estado de servicios críticos
    for service in docker glusterd portainer; do
        if ! systemctl is-active --quiet $service; then
            echo "[$timestamp] ALERT: Service $service is down" >> "$alert_file"
            alert_triggered=true
        fi
    done
    
    # Enviar alertas por email si está configurado
    if [[ $alert_triggered == true && -n "${CONFIG[MONITOR_ALERT_MAIL]}" ]]; then
        mail -s "Docker Cluster Alert" "${CONFIG[MONITOR_ALERT_MAIL]}" < "$alert_file"
    fi
}

# Manejo de errores y señales
handle_error() {
    local exit_code=$1
    local line_number=$2
    local error_message=$3
    
    error "Error en línea $line_number (código $exit_code): $error_message"
    
    # Intentar recuperar el sistema
    recover_system
}

# Recuperación del sistema
recover_system() {
    warn "Iniciando recuperación del sistema..."
    
    # Verificar y recuperar servicios críticos
    for service in docker glusterd portainer; do
        if ! systemctl is-active --quiet $service; then
            warn "Intentando recuperar servicio $service"
            systemctl restart $service || true
        fi
    done
    
    # Verificar y recuperar volumen GlusterFS
    if gluster volume info ${CONFIG[VOLUMEN_GLS]} &>/dev/null; then
        if ! gluster volume status ${CONFIG[VOLUMEN_GLS]} | grep -q "Status: Started"; then
            warn "Intentando recuperar volumen ${CONFIG[VOLUMEN_GLS]}"
            gluster volume start ${CONFIG[VOLUMEN_GLS]} force || true
        fi
    fi
    
    # Verificar y recuperar red overlay
    if docker network ls | grep -q "cluster-net"; then
        if ! docker network inspect cluster-net &>/dev/null; then
            warn "Intentando recuperar red overlay"
            docker network create --driver overlay --attachable cluster-net || true
        fi
    fi
    
    # Verificar y recuperar Portainer
    if ! docker service ls | grep -q "portainer"; then
        warn "Intentando recuperar servicio Portainer"
        setup_swarm || true
    fi
    
    # Verificar integridad de datos
    verify_data_integrity
    
    warn "Recuperación del sistema completada"
}

# Verificar integridad de datos
verify_data_integrity() {
    local issues=0
    
    # Verificar integridad de certificados
    if ! openssl verify -CAfile "${CONFIG[CERT_DIR]}/ca.crt" "${CONFIG[CERT_DIR]}/node.crt" &>/dev/null; then
        warn "Certificados corruptos, regenerando..."
        setup_certificates
        ((issues++))
    fi
    
    # Verificar integridad de tokens
    for token_type in manager worker; do
        local token_file="${CONFIG[TOKEN_DIR]}/${token_type}_token.enc"
        if [[ -f "$token_file" ]] && ! decrypt_token "$token_file" &>/dev/null; then
            warn "Token de $token_type corrupto, regenerando..."
            if [[ "$ES_PRIMARIO" == true ]]; then
                encrypt_token "$(docker swarm join-token $token_type -q)" > "$token_file"
            fi
            ((issues++))
        fi
    done
    
    # Verificar integridad de configuración
    if ! validate_config &>/dev/null; then
        warn "Configuración corrupta, restaurando desde backup..."
        restore_last_backup
        ((issues++))
    fi
    
    return $issues
}

# Restaurar último backup válido
restore_last_backup() {
    local backup_dir="${CONFIG[BACKUP_DIR]}"
    local latest_backup=$(ls -t "$backup_dir" 2>/dev/null | head -n1)
    
    if [[ -n "$latest_backup" ]]; then
        if verify_checksum "$backup_dir/$latest_backup"; then
            restore_backup "$backup_dir/$latest_backup"
        else
            warn "Checksum del último backup inválido, buscando backup válido..."
            for backup in $(ls -t "$backup_dir"); do
                if verify_checksum "$backup_dir/$backup"; then
                    restore_backup "$backup_dir/$backup"
                    break
                fi
            done
        fi
    fi
}

# Configurar traps mejorados
trap 'handle_error $? ${LINENO} "$BASH_COMMAND"' ERR
trap cleanup EXIT INT TERM

# Función principal modificada
main() {
    # Cargar configuración
    load_config
    load_env
    validate_config
    
    # Verificar integridad del sistema
    verify_data_integrity
    
    # Configurar monitoreo
    setup_monitoring
    
    # Crear backup inicial
    backup_config
    generate_checksum "${CONFIG[BACKUP_DIR]}/$(date +%Y%m%d_%H%M%S)"
    
    # Registrar acciones de rollback
    register_rollback "restore_last_backup"
    
    setup_logging
    check_root
    check_dependencies
    detect_os
    setup_os_commands
    check_disk_space
    validate_args
    verify_ports
    setup_user_groups
    
    # Instalar Docker con rollback
    if ! command -v docker &>/dev/null; then
        register_rollback "apt-get remove -y docker-ce docker-ce-cli containerd.io || true"
        install_docker
    fi
    
    info "Iniciando configuración con modo: $MODO_CLUSTER"
    info "Rol del nodo: $ROL_NODO"
    [[ -n "$OTROS_NODOS" ]] && info "Nodos adicionales: $OTROS_NODOS"
    
    # Crear directorios con rollback
    register_rollback "rm -rf ${CONFIG[BRICK_PATH]} ${CONFIG[SHARED_PATH]}/volumes"
    setup_directories "${CONFIG[BRICK_PATH]}" "${CONFIG[SHARED_PATH]}/volumes"
    
    # Configurar GlusterFS con rollback
    if ! command -v glusterfs &>/dev/null; then
        register_rollback "apt-get remove -y glusterfs-server glusterfs-client || true"
    fi
    setup_glusterfs
    
    case $MODO_CLUSTER in
        nuevo)
            if [[ "$ES_PRIMARIO" == true ]]; then
                # Registrar rollback para volumen GlusterFS
                register_rollback "gluster volume stop ${CONFIG[VOLUMEN_GLS]} || true"
                register_rollback "gluster volume delete ${CONFIG[VOLUMEN_GLS]} || true"
                setup_gluster_volume $OTROS_NODOS
                
                # Registrar rollback para Swarm
                register_rollback "docker swarm leave --force || true"
                setup_swarm
                info "Cluster creado exitosamente"
                info "Tokens encriptados guardados en ${CONFIG[TOKEN_DIR]}"
                info "Acceda a Portainer en: http://$NODO_PRIMARIO:${CONFIG[PORTAINER_HTTP_PORT]}"
            else
                # Desencriptar token según rol
                local token_file="${CONFIG[TOKEN_DIR]}/${ROL_NODO}_token.enc"
                local token=$(decrypt_token "$token_file")
                docker swarm join \
                --token "$token" \
                --ca-cert "${CONFIG[CERT_DIR]}/ca.crt" \
                --cert "${CONFIG[CERT_DIR]}/node.crt" \
                --key "${CONFIG[CERT_DIR]}/node.key" \
                $NODO_PRIMARIO:2377
                info "Nodo unido al cluster exitosamente"
            fi
            ;;
        unir)
            # Desencriptar token según rol
            local token_file="${CONFIG[TOKEN_DIR]}/${ROL_NODO}_token.enc"
            local token=$(decrypt_token "$token_file")
            docker swarm join --token "$token" $NODO_PRIMARIO:2377
            info "Nodo unido al cluster exitosamente"
            ;;
        agregar)
            info "Tokens encriptados para nuevos nodos:"
            info "Manager: $(encrypt_token "$(docker swarm join-token manager -q)")"
            info "Worker: $(encrypt_token "$(docker swarm join-token worker -q)")"
            info "Estado actual del cluster:"
            docker node ls
            ;;
    esac
    
    info "Configuración completada exitosamente"
}

# Procesar argumentos y ejecutar
source <(curl -s https://raw.githubusercontent.com/ko1nksm/getopts-sh/master/getopts.sh)
DEFINE_ARGS='
    m/master:   IP del nodo primario
    n/nodes:    IPs de otros nodos (separadas por comas)
    c/cluster:  Modo del cluster (nuevo,unir,agregar)
    r/role:     Rol del nodo (manager,worker)
    t/token:    Token para unirse al cluster
'

eval "$(getopts.sh)"
[[ -z "$NODO_PRIMARIO" ]] && error "Debe especificar --master"

main "$@"
