#!/bin/bash
set -e # Exit immediately if a command fails
echo "--- Starting Environment Setup ---"

sudo apt update

#Enable SCTP (for AMF communication)
sudo modprobe sctp
echo "sctp" | sudo tee -a /etc/modules

# Install build tools
sudo apt install -y make gcc

# Clone and install gtp5g
if [ ! -d "gtp5g" ]; then
    git clone https://github.com/free5gc/gtp5g.git
fi
cd gtp5g
# Check out a compatible tag, like v0.8.1
git checkout v0.8.1
# Compile and install
make && sudo make install

# Verify installation (should see 'gtp5g' in the list)
if [[ $(lsmod | grep -c "gtp") -eq 0 ]]
then
    sudo modprobe gtp5g # adding manually
fi
#retuning to orginal folder
cd .. 

#enabling ip forwading
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

#installing microk8s
sudo snap install microk8s --classic
sudo usermod -a -G microk8s $USER

#Allow Unsafe Sysctls
echo '--allowed-unsafe-sysctls "net.ipv4.ip_forward"' | sudo tee -a /var/snap/microk8s/current/args/kubelet

sudo microk8s stop && sudo microk8s start

echo "--- Environment ready! ---"
echo "CRITICAL: You must log out and log back in, then run setup_k8s.sh"