import os
import json
import subprocess
from ruamel.yaml import YAML

# Load configuration
try:
    with open("config/config.json", "r") as f:
        CONFIG = json.load(f)
except FileNotFoundError:
    print("Error: config/config.json not found. Using default values.")
    CONFIG = {}
except json.JSONDecodeError:
    print("Error: Invalid JSON in config/config.json. Using default values.")
    CONFIG = {}

# Configuration constants
HARDENER_REPORT_PATH = CONFIG.get("paths", {}).get("hardener_report", "hardener_report.json")
HARDENING_FOLDER_PATH = CONFIG.get("paths", {}).get("hardening_folder", "free5gc_hardening")
NAMESPACE = CONFIG.get("kubernetes", {}).get("namespace", "free5gc")
HELM_CHART_REPO = CONFIG.get("kubernetes", {}).get("helm", {}).get("chart_repo", "towards5gs")
HELM_CHART_NAME = CONFIG.get("kubernetes", {}).get("helm", {}).get("chart_name", "free5gc")

def initialize():
    # Create hardening folder
    if not os.path.exists(HARDENING_FOLDER_PATH):
        os.makedirs(HARDENING_FOLDER_PATH)
    else:
        # If the hardening folder already exists, remove it and create a new one to ensure a clean environment
        if os.path.exists(os.path.join(HARDENING_FOLDER_PATH, HELM_CHART_NAME)):
            try:
                target_path = os.path.join(HARDENING_FOLDER_PATH, HELM_CHART_NAME)
                for root, dirs, files in os.walk(target_path, topdown=False):
                    for file in files:
                        os.remove(os.path.join(root, file))
                    for dir in dirs:
                        os.rmdir(os.path.join(root, dir))
                os.rmdir(target_path)
            except OSError as e:
                print(f"Error occurred while removing existing Helm chart: {e}")
    
    # Pull Helm chart for free5gc and extract it to the hardening folder
    try:
        chart_reference = f"{HELM_CHART_REPO}/{HELM_CHART_NAME}"
        output = subprocess.check_output(["microk8s", "helm", "pull", chart_reference, "--untar", "--untardir", HARDENING_FOLDER_PATH])
    except subprocess.CalledProcessError as e:
        print(f"Error occurred while pulling Helm chart: {e}")

def harden_pod_security(pod_security_report):
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    for pod in pod_security_report["pods"]:
        chart_name = pod["labels"].get("app.kubernetes.io/name", [])
        chart_path = os.path.join(HARDENING_FOLDER_PATH, f"{HELM_CHART_NAME}/charts/{chart_name}")
        if os.path.exists(chart_path):

            with open(os.path.join(chart_path, "values.yaml"), "r") as f:
                values = yaml.load(f)

            for violation in pod["violations"]:
                print(f"Hardening violation {violation} for pod {pod['pod_name']} in chart {chart_name}")
                for component in values:
                    print(f"Hardening component {component} for pod {pod['pod_name']} in chart {chart_name}")
            
        else:
            print(f"[WARNING] Chart {chart_name} not found for pod {pod['pod_name']}")

def harden_infrastructure(infrastructure_report):
    # Implement hardening logic based on infrastructure report
    pass

def harden_network_policies(network_policy_report):
    # Implement hardening logic based on network policy report
    pass

def make_report():
    pass

if __name__ == "__main__":

    # Initialize hardening environment and pull Helm charts
    initialize()

    # Load reports and apply hardening measures for pod security
    try:
        with open("pod_security_report.json", "r") as f:
            pod_security_report = json.load(f)
            harden_pod_security(pod_security_report)
    except FileNotFoundError:
        print("Pod security report not found.")
    
    # Load reports and apply hardening measures for infrastructure
    try:
        with open("infrastructure_report.json", "r") as f:
            infrastructure_report = json.load(f)
            harden_infrastructure(infrastructure_report)
    except FileNotFoundError:
        print("Infrastructure report not found.")

    # Load reports and apply hardening measures for network policies
    try:
        with open("network_policy_report.json", "r") as f:
            network_policy_report = json.load(f)
            harden_network_policies(network_policy_report)
    except FileNotFoundError:
        print("Network policy report not found.")