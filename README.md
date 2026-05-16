# scripts_ok

Colección de utilidades pequeñas para administración de Linux/WSL2/macOS y para mantener sesiones de Google Colab visibles. Todos los scripts incluyen un comentario inicial que resume su propósito.

> **Importante:** `linux-zram-swap`, `Linux + WSL2 + macOS-zram-swap` y `disable-services` modifican configuración del sistema. Revísalos antes de ejecutarlos y úsales con `sudo` solo en equipos donde aceptes esos cambios.

## Estado funcional por archivo

| Archivo | Estado | Qué realiza | Ejecución recomendada |
| --- | --- | --- | --- |
| `noclosedcolab` | Funcional como snippet de navegador | Ejecuta un clic periódico cada 10 minutos sobre el botón `#toggle-header-button` de Google Colab. | Pegar en la consola del navegador dentro de una pestaña de Colab. |
| `diagnostic-server` | Funcional en Linux con systemd; tolera comandos faltantes | Imprime diagnóstico de hardware, RAM, discos, servicios, red, suspensión, telemetría y últimos eventos relacionados. | `sudo ./diagnostic-server` |
| `disable-services` | Funcional en Linux con systemd y apt opcional | Cambia el equipo a perfil servidor: target multiusuario, sin GUI/suspensión, sin servicios de escritorio comunes y con logs/swap optimizados. | `sudo ./disable-services` |
| `linux-zram-swap` | Funcional en Linux nativo con systemd | Instala/configura `zram-tools`, swapfile persistente, prioridades de swap y parámetros `sysctl`. | `sudo ./linux-zram-swap` |
| `Linux + WSL2 + macOS-zram-swap` | Funcional como script multiplataforma seguro | En Linux nativo aplica zram + swapfile; en WSL2/macOS muestra estado y recomendaciones sin forzar cambios no soportados. | `sudo ./Linux\ +\ WSL2\ +\ macOS-zram-swap apply` o `./Linux\ +\ WSL2\ +\ macOS-zram-swap status` |

## Interrelaciones sugeridas

```text
diagnostic-server
  ├── Audita estado antes de tocar el servidor
  ├── Valida cambios hechos por disable-services
  └── Valida memoria/swap después de linux-zram-swap o auto-mem-tune

linux-zram-swap
  └── Especializado en Linux nativo con zram-tools + systemd

Linux + WSL2 + macOS-zram-swap
  ├── Alternativa más segura/multiplataforma para revisar memoria
  ├── Aplica cambios solo en Linux nativo compatible
  └── En WSL2/macOS entrega guía porque no existe zram nativo equivalente gestionable igual

disable-services
  ├── Puede ejecutarse después de diagnostic-server
  └── Conviene validarlo luego con diagnostic-server

noclosedcolab
  └── Independiente; no interactúa con los scripts de servidor
```

## Uso detallado

### `noclosedcolab`

1. Abre una notebook en Google Colab.
2. Abre la consola del navegador.
3. Pega el contenido de `noclosedcolab` y presiona Enter.

Caso práctico: mantener visible una notebook durante una descarga larga, entrenamiento liviano o monitoreo de resultados. Google Colab puede aplicar sus propias políticas de desconexión, por lo que este snippet no garantiza recursos ilimitados.

### `diagnostic-server`

```bash
chmod +x diagnostic-server
sudo ./diagnostic-server | tee diagnostic-server.log
```

Casos prácticos:

- Revisar si un servidor está arrancando en modo gráfico o modo servidor.
- Confirmar si suspensión/hibernación está activa.
- Ver servicios de escritorio que consumen RAM en un equipo usado como servidor.
- Comprobar red, IP y estado de Tailscale si está instalado.

### `disable-services`

```bash
chmod +x disable-services
sudo ./disable-services
```

Variables útiles:

```bash
sudo NO_UPGRADE=1 ./disable-services      # no ejecuta apt upgrade
sudo REMOVE_FLATPAK=0 ./disable-services  # conserva flatpak
```

Casos prácticos:

- Convertir un Ubuntu/Mint de escritorio en un equipo tipo servidor sin entorno gráfico.
- Evitar suspensión en un servidor casero al cerrar tapa o quedar inactivo.
- Reducir servicios innecesarios como Bluetooth, impresión, Avahi o ModemManager.

### `linux-zram-swap`

```bash
chmod +x linux-zram-swap
sudo ./linux-zram-swap
swapon --show
zramctl
free -h
```

Variables útiles:

```bash
sudo ZRAM_PERCENT=60 SWAP_PERCENT=100 SWAPPINESS=10 ./linux-zram-swap
```

Casos prácticos:

- Mejorar tolerancia a picos de memoria en VPS o servidores con poca RAM.
- Priorizar zram sobre swapfile para reducir uso de disco.
- Crear swapfile persistente si el sistema no tiene suficiente swap.

### `Linux + WSL2 + macOS-zram-swap`

El nombre contiene espacios; ejecútalo escapando espacios o entre comillas:

```bash
chmod +x 'Linux + WSL2 + macOS-zram-swap'
./Linux\ +\ WSL2\ +\ macOS-zram-swap status
sudo ./Linux\ +\ WSL2\ +\ macOS-zram-swap apply
```

Casos prácticos:

- Usar `status` en WSL2 para ver memoria/swap y recordar que el ajuste principal va en `%UserProfile%\.wslconfig`.
- Usar `status` en macOS para revisar compresión/swap sin intentar cambios inseguros.
- Usar `apply` en Linux nativo cuando se quiere una configuración autocontenida de zram + swapfile sin depender de `zram-tools`.

## Requisitos

- Bash.
- Linux con systemd para los scripts que cambian servicios o memoria del sistema.
- `apt-get` solo es obligatorio cuando se requiere instalar/purgar paquetes en distribuciones Debian/Ubuntu/Mint.
- Permisos root para cambios de sistema.
- Navegador web para `noclosedcolab`.

## Validación rápida sin aplicar cambios destructivos

```bash
bash -n diagnostic-server disable-services linux-zram-swap 'Linux + WSL2 + macOS-zram-swap'
node --check noclosedcolab
./Linux\ +\ WSL2\ +\ macOS-zram-swap status
```
