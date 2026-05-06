#!/bin/bash

echo "--- Starting K8S Setup ---"

INTERFACE_NAME=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Detected interface: $INTERFACE_NAME"

#enabling addons
sg microk8s -c "microk8s enable community"
sg microk8s -c "microk8s enable dns"
sg microk8s -c "microk8s enable hostpath-storage" 
sg microk8s -c "microk8s enable helm3"
sg microk8s -c "microk8s enable multus"

#setting up folder for pv
sudo mkdir -p /var/snap/microk8s/common/default-storage/mongodb
sudo chown -R 999:999 /var/snap/microk8s/common/default-storage/mongodb

#adding mongodb pv to the cluster
sg microk8s -c "microk8s kubectl apply -f mongodb-pv.yaml"

#adding towards5gs/free5gc repo
sg microk8s -c "microk8s helm repo add towards5gs https://towards5gs.github.io/helm-charts/"
sg microk8s -c "microk8s helm repo update"

#creating name space
sg microk8s -c "microk8s kubectl create namespace free5gc"

#installing free5gc with changes to charts
sg microk8s -c "microk8s helm install free5gc-core towards5gs/free5gc \
  --namespace free5gc \
  --set mongodb.image.registry='docker.io' \
  --set mongodb.image.repository='library/mongo' \
  --set mongodb.image.tag='4.4.4' \
  --set mongodb.persistence.enabled=true \
  --set mongodb.persistence.storageClass=microk8s-hostpath \
  --set mongodb.podSecurityContext.fsGroup=999 \
  --set mongodb.containerSecurityContext.runAsUser=999 \
  --set global.n2network.masterIf=$INTERFACE_NAME \
  --set global.n3network.masterIf=$INTERFACE_NAME \
  --set global.n4network.masterIf=$INTERFACE_NAME \
  --set global.n6network.masterIf=$INTERFACE_NAME \
  --set global.n9network.masterIf=$INTERFACE_NAME"


echo "--- K8S ready! ---"


echo "--- Starting Kube-bench Setup ---"
# Download the latest Linux release
curl -L https://github.com/aquasecurity/kube-bench/releases/download/v0.7.3/kube-bench_0.7.3_linux_amd64.tar.gz -o kube-bench.tar.gz

# Extract it
tar -xvf kube-bench.tar.gz

# Move it to your path so you can run it anywhere
sudo mv kube-bench /usr/local/bin/

#sudo kube-bench run --targets node --benchmark cis-1.24-microk8s --config-dir $(pwd)/cfg --json > baseline.json

sudo ln -s /snap/bin/microk8s.kubectl /usr/local/bin/kubectl
sudo ln -s /snap/bin/microk8s.kubectl /usr/local/bin/kubelet

echo "--- kube-bench ready! ---"