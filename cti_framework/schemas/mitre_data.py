from typing import Dict, Any, Optional

# Offline Enterprise MITRE ATT&CK Dictionary
MITRE_ATTACK_DB: Dict[str, Dict[str, str]] = {
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": "Adversaries may transfer tools or other files from an external system into a compromised environment."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (PowerShell, Bash, Python) to execute commands."
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution."
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to avoid detection."
    },
    "T1071.001": {
        "name": "Web Protocols (HTTP/S)",
        "tactic": "Command and Control",
        "description": "Adversaries may use HTTP/S to blend C2 traffic with normal web communications."
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages with malicious attachments or links to gain initial access."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may exploit vulnerabilities in Internet-facing software or web applications to gain access."
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Adversaries may attempt to make an executable or script difficult to discover or analyze using encoding/packing."
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get detailed information about the operating system and hardware."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to dump credentials from the operating system to obtain account logon information."
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "Execution",
        "description": "Adversaries may abuse WMI to execute malicious commands and move laterally."
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "Persistence",
        "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon."
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses."
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use Valid Accounts to log into remote services such as SSH, RDP, or SMB."
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining access or persistence."
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel."
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Adversaries may modify or disable security tools, logging, or firewalls to avoid detection."
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "Impact",
        "description": "Adversaries may encrypt data on target systems to interrupt availability (Ransomware)."
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service attacks to degrade or block availability of targeted resources."
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": "Adversaries may delete or alter generated artifacts on a host system, such as event logs or files."
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "description": "Adversaries may rely on a user executing a malicious file or link to achieve code execution."
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "Persistence",
        "description": "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs (DLL hijacking)."
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Execution",
        "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code."
    },
    "T1132": {
        "name": "Data Encoding",
        "tactic": "Command and Control",
        "description": "Adversaries may encode data (Base64, XOR) to make the content of C2 traffic more difficult to detect."
    }
}

def enrich_mitre_technique(technique_id: str, suggested_name: Optional[str] = None) -> Dict[str, str]:
    """
    Enriches a MITRE technique ID with official Enterprise ATT&CK metadata.
    """
    clean_id = technique_id.strip().upper()
    if clean_id in MITRE_ATTACK_DB:
        info = MITRE_ATTACK_DB[clean_id]
        return {
            "technique_id": clean_id,
            "name": info["name"],
            "tactic": info["tactic"],
            "description": info["description"]
        }
    
    # Check parent ID if sub-technique (e.g., T1059.001 -> T1059)
    if "." in clean_id:
        parent_id = clean_id.split(".")[0]
        if parent_id in MITRE_ATTACK_DB:
            parent = MITRE_ATTACK_DB[parent_id]
            return {
                "technique_id": clean_id,
                "name": suggested_name or f"{parent['name']} (Subtechnique)",
                "tactic": parent["tactic"],
                "description": parent["description"]
            }

    # Fallback heuristic tactic based on common ID ranges
    return {
        "technique_id": clean_id,
        "name": suggested_name or "Mapped Adversary Technique",
        "tactic": "Defense Evasion" if clean_id.startswith("T10") else "Execution",
        "description": "Identified behavior from threat intelligence reporting."
    }
