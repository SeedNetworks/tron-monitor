1. Установка npm (Node Package Manager) и pm2 (Daemon Process Manager): sudo apt install npm && sudo npm install pm2@latest -g && pm2 startup
2. Деплой (запускать в папке ./tron-monitor): npm run deploy
Консоль лог: pm2 log tronmonitor 
Рестарт: pm2 restart tronmonitor 
Остановка: pm2 stop tronmonitor 
Старт: pm2 start tronmonitor 
