# 5G Network Function (NF) Hardening Automator

## Setting up the Env
### Step 1. Install Ubuntu server (tested version: 24.10):
You can also use minikube or kind but the installetion procces will be different.
### Step 2. Setting up the machine
Free5GC requires specific kernel modules that aren't enabled by default.
#### 1. Enable SCTP (for AMF communication):
```bash
sudo modprobe sctp
echo "sctp" | sudo tee -a /etc/modules
```
#### 2.Install gtp5g (Required for UPF):
The User Plane Function (UPF) requires this custom 5G kernel module to handle packet forwarding.
```bash
# Install build tools
sudo apt update
sudo apt install -y make gcc git

# Clone and install gtp5g
git clone https://github.com/free5gc/gtp5g.git
cd gtp5g

# Check out a compatible tag, like v0.8.1
git checkout v0.8.1

# Compile and install
make
sudo make install

# Verify installation (should see 'gtp5g' in the list)
lsmod | grep gtp
```

#### 3.Enable IP Forwarding:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```
### Step 3.Install and Configure MicroK8s
We need to enable specific addons and allow "unsafe" configurations for the UPF to work.
#### 1.Install MicroK8s
```bash
sudo snap install microk8s --classic
sudo usermod -a -G microk8s $USER
# Log out and log back in for group changes to take effect
```
#### 2.Enable Addons:
```bash
microk8s enable community
microk8s enable dns 
microk8s enable hostpath-storage 
microk8s enable helm3
microk8s enable multus
```

#### 3.Allow Unsafe Sysctls:
The UPF pod needs to modify kernel networking parameters.
```bash
sudo nano /var/snap/microk8s/current/args/kubelet
# Add this line to the end:
--allowed-unsafe-sysctls "net.ipv4.ip_forward"

sudo microk8s stop && sudo microk8s start
```

### Step 4.Setup Persistent Storage for MongoDB

#### 1.Create the directory:
```bash
sudo mkdir -p /var/snap/microk8s/common/default-storage/mongodb
sudo chown -R 999:999 /var/snap/microk8s/common/default-storage/mongodb
```
#### 2.Apply the PersistentVolume:
```bash
microk8s kubectl apply -f mongodb-pv.yaml
```

### Step 5.Deploy free5GC via Helm
Now we use the optimized command we built to override the broken defaults.

#### 1.Add the repository:

```Bash
microk8s helm repo add towards5gs https://towards5gs.github.io/helm-charts/
microk8s helm repo update
```

#### 2.installing free5gc with changes to charts

```bash
microk8s kubectl create namespace free5gc

microk8s helm install free5gc-core towards5gs/free5gc \
  --namespace free5gc \
  --set mongodb.image.registry="docker.io" \
  --set mongodb.image.repository="library/mongo" \
  --set mongodb.image.tag="4.4.4" \
  --set mongodb.persistence.enabled=true \
  --set mongodb.persistence.storageClass=microk8s-hostpath \
  --set mongodb.podSecurityContext.fsGroup=999 \
  --set mongodb.containerSecurityContext.runAsUser=999 \
  --set global.n2network.masterIf=YOUR_INTERFACE_NAME \
  --set global.n3network.masterIf=YOUR_INTERFACE_NAME \
  --set global.n4network.masterIf=YOUR_INTERFACE_NAME \
  --set global.n6network.masterIf=YOUR_INTERFACE_NAME \
  --set global.n9network.masterIf=YOUR_INTERFACE_NAME
```


    
## Roadmap

- add setup_env.sh
- add kube-bench
- add setup_k8s.sh
- develop "Auditor" (Python)
- develop the "Hardener" (Remediation)
- improving readme

