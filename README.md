# 5G Network Function (NF) Hardening Automator

## Setting up the Env
### Step 1. Install Ubuntu server (tested version: 24.10):
You can also use minikube or kind but the installetion procces will be different.
### Step 2. Setting up the machine
#### 1.Git clone the repo into specif folder than run this script
```bash
./setup_env.sh
```
#### 2.Setup mongodb-pv
change value YOUR_NODE_NAME_HERE to the name of your node before next step

#### 3.Restart the machine and then run second script:
```bash
./setup_k8s.sh
```
## Roadmap

- add kube-bench
- develop "Auditor" (Python)
- develop the "Hardener" (Remediation)
- improving readme

