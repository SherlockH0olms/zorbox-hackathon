cd /opt/CAPEv2/installer

# KVM quraşdırma skriptini yükləyin
sudo chmod +x kvm-qemu.sh

# KVM qurulumu (username əvəzinə öz istifadəçi adınızı yazın)
sudo ./kvm-qemu.sh all cape | tee kvm-qemu.log

# Virtual Manager qurulumu (ixtiyari, amma tövsiyə olunur)
sudo ./kvm-qemu.sh virtmanager cape | tee virt-manager.log

# Reboot edin
sudo reboot
