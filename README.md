# 5G Network Function (NF) Hardening Automator

## Setting up the Env
### Step 1. Install Ubuntu server (tested version: 24.10):
You can also use minikube or kind but the installetion procces will be different.
### Step 2. Setting up the machine
#### 1.Git clone the repo into specif folder than run this script
```bash
./setup_env.sh
```
#### 2. Restart the machine then run second script:
```bash
./setup_k8s.sh
```
## Roadmap

- add setup_env.sh
- add kube-bench
- add setup_k8s.sh
- develop "Auditor" (Python)
- develop the "Hardener" (Remediation)
- improving readme

