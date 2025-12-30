import logging
import subprocess
import shutil
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

from logging_utils import get_logger
from models import Finding
import risk_model

logger = get_logger(__name__)

def _get_nmap_path() -> str | None:
    return shutil.which("nmap")

def _port_risk(port_info: Dict[str, Any]) -> Finding:
    port = port_info.get("port")
    proto = (port_info.get("protocol") or "tcp").lower()
    service = port_info.get("service") or "unknown"
    state = port_info.get("state") or "open"

    # Risk Scoring
    low_risk_ports = {80, 443} # HTTP/S is expected
    med_risk_ports = {22, 25, 53, 110, 143, 465, 587, 993, 995, 3306, 5432} # Common but should be secured
    
    if port in low_risk_ports:
        likelihood, impact = 1, 2
    elif port in med_risk_ports:
        likelihood, impact = 2, 3
    else:
        likelihood, impact = 3, 3 # Unusual ports

    desc = f"Nmap detected an {state} {proto} port {port} (service: {service})."
    rec = "Verify if this port needs to be exposed. If not, close it via firewall."

    return risk_model.create_finding(
        id=f"NMAP-{proto.upper()}-{port}",
        title=f"Open Port {port}/{proto} ({service})",
        category="Network Exposure",
        description=desc,
        recommendation=rec,
        likelihood=likelihood,
        impact=impact,
        source="nmap-real"
    )

def run_nmap_scan(target: str, scan_type: str = "fast", ports: str | None = None) -> tuple[list[Finding], dict]:
    """
    Executes a REAL nmap scan using the system binary.
    Requires 'nmap' to be installed and in PATH.
    """
    if not target: return [], {}

    nmap_path = _get_nmap_path()
    if not nmap_path:
        error_msg = "Nmap binary not found in system PATH. Please install Nmap from https://nmap.org/download.html"
        logger.error(error_msg)
        return [], {"error": "nmap_missing", "message": error_msg}

    # Build Command
    # -oX - : Output XML to stdout
    cmd = [nmap_path, "-oX", "-"]
    
    if scan_type == "fast":
        cmd.append("-F") # Fast mode (top 100 ports)
    elif scan_type == "intense":
        cmd.extend(["-T4", "-A", "-v"])
    
    if ports:
        cmd.extend(["-p", ports])
    
    cmd.append(target)
    
    logger.info(f"Running Nmap: {' '.join(cmd)}")
    
    try:
        # Run Nmap
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            logger.error(f"Nmap failed: {result.stderr}")
            return [], {"error": "scan_failed", "stderr": result.stderr}

        # Parse XML
        root = ET.fromstring(result.stdout)
        findings = []
        raw_ports = []
        
        for host in root.findall("host"):
            ports_node = host.find("ports")
            if ports_node is None: continue
            
            for p in ports_node.findall("port"):
                state_el = p.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                
                port_id = int(p.get("portid"))
                protocol = p.get("protocol")
                
                service_el = p.find("service")
                service_name = service_el.get("name") if service_el is not None else "unknown"
                
                info = {
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "state": "open"
                }
                raw_ports.append(info)
                findings.append(_port_risk(info))

        return findings, {"raw_output": result.stdout, "parsed_ports": raw_ports}

    except subprocess.TimeoutExpired:
        return [], {"error": "timeout", "message": "Scan timed out after 120s"}
    except Exception as e:
        logger.error(f"Nmap execution error: {e}")
        return [], {"error": "execution_error", "message": str(e)}

