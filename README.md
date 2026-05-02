# scripts_ok

Esta carpeta contiene scripts cuyo funcionamiento ha sido comprobado. A continuación, se describe el propósito de cada archivo:

- **`noclosedcolab`**: Script en JavaScript que mantiene activa una sesión en Google Colab simulando un clic en un botón cada 10 minutos.


para el  Linux + WSL2 + macOS-zram-swap se debe ejecutar antes 

sudo nano /usr/local/sbin/auto-mem-tune.sh
se pega
sudo chmod 0755 /usr/local/sbin/auto-mem-tune.sh
sudo /usr/local/sbin/auto-mem-tune.sh
swapon --show
zramctl
