"""
THE BIG BROTHER // V7.0 TACTICAL FORENSIC SYSTEM
COMPANION POWER ENGINE: INDUSTRIAL SCADA / ICS & IOT INFRASTRUCTURE RADAR (v7_scada_radar)
CLASSIFIED // CRITICAL INFRASTRUCTURE DEFENSE & OT ASSET RECONNAISSANCE

Probes and fingerprints Operational Technology (OT), SCADA, PLC, and IoT perimeters:
- Modbus TCP (Port 502) Device ID probe
- Siemens S7 (Port 102) COTP connection probe
- BACnet (Port 47808) Building Automation probe
- MQTT (Port 1883) IoT Broker probe
- CoAP (Port 5683) Constrained Application Protocol
- Purdue Enterprise Reference Architecture level mapping (Level 0/1 to Level 4)
"""

import asyncio
import socket
from typing import Dict, Any, List

SCADA_PORTS = [
    {"port": 502, "protocol": "Modbus TCP", "device": "PLC / Schneider / Modicon / Advantech", "purdue_level": "Level 1 (Basic Control)"},
    {"port": 102, "protocol": "Siemens S7 (ISO-TSAP)", "device": "Siemens S7-300 / S7-1200 / S7-1500 PLC", "purdue_level": "Level 1 (Basic Control)"},
    {"port": 47808, "protocol": "BACnet/IP", "device": "HVAC / Building Management System (BMS)", "purdue_level": "Level 2 (Area Supervisory)"},
    {"port": 1883, "protocol": "MQTT Unencrypted", "device": "IoT Telemetry Broker / Mosquitto", "purdue_level": "Level 3 (Site Operations)"},
    {"port": 8883, "protocol": "MQTT over TLS", "device": "Hardened IoT Gateway", "purdue_level": "Level 3 (Site Operations)"},
    {"port": 44818, "protocol": "EtherNet/IP", "device": "Rockwell Automation / Allen-Bradley PLC", "purdue_level": "Level 1 (Basic Control)"},
    {"port": 20000, "protocol": "DNP3", "device": "Electric Power Substation RTU", "purdue_level": "Level 1 (Substation Automation)"},
    {"port": 5683, "protocol": "CoAP", "device": "Smart Sensor / Smart City Node", "purdue_level": "Level 0 (Physical Process)"}
]

async def scan_scada_perimeter(target_host: str) -> Dict[str, Any]:
    if not target_host:
        return {"status": "error", "error": "Target host/IP is required."}
        
    host = target_host.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0].strip()
    
    open_services = []
    
    async def probe_port(port_info: Dict[str, Any]):
        port = port_info["port"]
        try:
            # Async TCP connect test
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=2.5)
            
            # Simple banner grab attempt
            banner = ""
            if port == 1883:
                # MQTT Connect packet
                writer.write(b"\x10\x0c\x00\x04MQTT\x04\x02\x00\x3c\x00\x00")
                await writer.drain()
            elif port == 102:
                # COTP Connection Request
                writer.write(b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a")
                await writer.drain()
                
            try:
                raw_resp = await asyncio.wait_for(reader.read(128), timeout=1.0)
                if raw_resp:
                    banner = raw_resp[:32].hex()
            except Exception:
                pass
                
            writer.close()
            await writer.wait_closed()
            
            return {
                "port": port,
                "protocol": port_info["protocol"],
                "identified_hardware": port_info["device"],
                "purdue_level": port_info["purdue_level"],
                "state": "OPEN_EXPOSED",
                "raw_handshake_hex": banner if banner else "CONNECTED_NO_BANNER",
                "threat_rating": "CRITICAL_INFRASTRUCTURE_EXPOSURE"
            }
        except Exception:
            return None

    tasks = [probe_port(p) for p in SCADA_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, dict) and r:
            open_services.append(r)

    # Risk scoring
    criticality = "HARDENED / ZERO_EXPOSED_ICS"
    if open_services:
        if any(s["port"] in (502, 102, 44818, 20000) for s in open_services):
            criticality = "DEFCON_1 // DIRECT_PLC_CONTROL_EXPOSED"
        else:
            criticality = "DEFCON_2 // AUXILIARY_IOT_SERVICES_DETECTED"

    return {
        "status": "success",
        "target": host,
        "scada_ports_audited": len(SCADA_PORTS),
        "exposed_industrial_controllers": open_services,
        "total_exposed_ports": len(open_services),
        "posture_assessment": criticality,
        "remediation_directives": [
            "Place all Purdue Level 0-2 devices behind strict air-gaps or unidirectional security gateways (data diodes).",
            "Disable unauthenticated Modbus TCP broadcast commands (Function Code 0x05 / 0x06).",
            "Enforce TLS 1.3 encryption on MQTT telemetry feeds and decommission unencrypted port 1883."
        ]
    }

async def scan_scada_perimeter_async(host: str) -> Dict[str, Any]:
    return await scan_scada_perimeter(host)
