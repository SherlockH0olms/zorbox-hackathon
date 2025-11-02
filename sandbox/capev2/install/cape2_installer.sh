# CAPEv2 repository-ni klonlayın
cd /opt
sudo git clone https://github.com/kevoreilly/CAPEv2.git
cd CAPEv2

# Quraşdırma skriptini icra edin
cd installer
sudo chmod +x cape2.sh

# Tam quraşdırma
sudo ./cape2.sh base cape | tee cape.log

# Sistem servisləri:
# - cape.service
# - cape-processor.service  
# - cape-web.service
# - cape-rooter.service

# Reboot edin
sudo reboot