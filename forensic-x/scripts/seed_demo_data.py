"""
FORENSIC-X — Realistic DFIR Demo Data Seeder
scripts/seed_demo_data.py
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.db.session import AsyncSessionLocal
from app.db.init_db import init_db
from app.detection.service import seed_default_rules
from app.cases.models import Case
from app.cases.schemas import CasePriority, CaseStatus, CaseClassification
from app.evidence.models import Evidence, EvidenceHash, ChainOfCustody
from app.iocs.models import Indicator, IOCMatch
from app.timeline.models import TimelineEvent
from app.incidents.models import Incident, IncidentTask, AnalystNote
from app.users.models import User
from app.core.hashing import calculate_bytes_hashes
from app.config import settings


async def seed_demo():
    print("[*] Starting FORENSIC-X Demo Data Seeding...")
    async with AsyncSessionLocal() as db:
        # 1. Initialize core DB roles, superadmin, and detection rules
        await init_db(db)
        await seed_default_rules(db)

        # Retrieve admin user
        admin_res = await db.execute(select(User).where(User.email == settings.ADMIN_EMAIL))
        admin = admin_res.scalar_one()

        # 2. Create Realistic DFIR Case 1: Operation Cobalt Shadow
        case1_res = await db.execute(select(Case).where(Case.case_number == "CASE-2026-0001"))
        case1 = case1_res.scalar_one_or_none()

        if not case1:
            case1 = Case(
                case_number="CASE-2026-0001",
                name="Operation Cobalt Shadow — Active C2 Infiltration",
                description="Investigation into unauthorized lateral movement, LSASS credential dumping, and external C2 beaconing on corporate domain controller DC-01.",
                priority="critical",
                status="in_progress",
                classification="unauthorized_access",
                lead_investigator_id=admin.id,
                tags="apt,cobalt-strike,domain_compromise,active_incident",
            )
            case1.users.append(admin)
            db.add(case1)
            await db.commit()
            await db.refresh(case1)
            print("  [+] Created Case: CASE-2026-0001")

            # Add Evidence 1: Memory dump
            mem_data = b"MEMORY_DUMP_VOLATILITY_SAMPLE_COBALT_STRIKE_BEACON_4522"
            mem_hashes = calculate_bytes_hashes(mem_data)
            ev1_path = settings.evidence_upload_path / str(case1.id)
            ev1_path.mkdir(parents=True, exist_ok=True)
            mem_file = ev1_path / "dc01_winpmem_raw.dmp"
            with open(mem_file, "wb") as f:
                f.write(mem_data)

            ev1 = Evidence(
                case_id=case1.id,
                evidence_number="EVD-2026-0001",
                name="DC-01 Volatile Memory Acquisition",
                description="Live RAM dump acquired via WinPmem 4.0 during containment triage.",
                original_filename="dc01_winpmem_raw.dmp",
                storage_path=str(mem_file),
                size_bytes=len(mem_data),
                mime_type="application/octet-stream",
                source_type="memory_dump",
                acquisition_method="winpmem",
                custodian="SOC Incident Responder John Doe",
                location_acquired="Server Room Rack 04, DC-01",
                status="verified",
                md5=mem_hashes["md5"],
                sha1=mem_hashes["sha1"],
                sha256=mem_hashes["sha256"],
            )
            ev1.hashes.append(EvidenceHash(hash_type="sha256", hash_value=mem_hashes["sha256"]))
            ev1.chain_of_custody.append(
                ChainOfCustody(
                    performed_by_id=admin.id,
                    action="collected",
                    transferred_to="FORENSIC-X Vault",
                    reason="Initial live RAM acquisition",
                    integrity_verified=True,
                    hash_at_action=mem_hashes["sha256"],
                    notes="Preserved in tamper-evident write-blocked environment",
                )
            )
            db.add(ev1)

            # Add Evidence 2: Security Event Log
            ev2_data = b"<Event><System><EventID>4624</EventID></System></Event>"
            ev2_hashes = calculate_bytes_hashes(ev2_data)
            ev2_file = ev1_path / "Security_EVTX_Export.xml"
            with open(ev2_file, "wb") as f:
                f.write(ev2_data)

            ev2 = Evidence(
                case_id=case1.id,
                evidence_number="EVD-2026-0002",
                name="Windows Security Event Log EVTX",
                description="Exported Windows security audit log spanning initial compromise window.",
                original_filename="Security_EVTX_Export.xml",
                storage_path=str(ev2_file),
                size_bytes=len(ev2_data),
                mime_type="application/xml",
                source_type="system_logs",
                acquisition_method="manual_upload",
                custodian="Domain Administrator",
                location_acquired="Domain Controller DC-01",
                status="in_analysis",
                md5=ev2_hashes["md5"],
                sha1=ev2_hashes["sha1"],
                sha256=ev2_hashes["sha256"],
            )
            db.add(ev2)
            await db.commit()
            print("  [+] Registered Evidence Artifacts for Case 1")

            # 3. Add Threat Indicators (IOCs)
            iocs = [
                Indicator(
                    case_id=case1.id,
                    ioc_type="ip",
                    value="185.220.101.5",
                    threat_type="c2_server",
                    severity="critical",
                    confidence=95,
                    tlp="amber",
                    description="Cobalt Strike Team Server IP observed in C2 traffic",
                    tags="c2,cobalt-strike,apt29",
                ),
                Indicator(
                    case_id=case1.id,
                    ioc_type="sha256",
                    value="a94a8fe5ccb19ba61c4c0873d391e987982fbbd3b4eb806e300d8b4e782627e2",
                    threat_type="malware_payload",
                    severity="critical",
                    confidence=90,
                    tlp="amber",
                    description="Mimikatz x64 binary hash (mimilib.dll)",
                    tags="credential_dumping,mimikatz",
                ),
                Indicator(
                    case_id=case1.id,
                    ioc_type="domain",
                    value="updates-microsoft-cdn.com",
                    threat_type="phishing_domain",
                    severity="high",
                    confidence=85,
                    tlp="green",
                    description="Typosquatted domain used for initial phishing payload distribution",
                    tags="phishing,typosquatting",
                ),
            ]
            db.add_all(iocs)
            await db.commit()
            print("  [+] Populated Threat Indicators (IOCs)")

            # 4. Add Chronological Timeline Events
            now = datetime.now(timezone.utc)
            timeline_events = [
                TimelineEvent(
                    case_id=case1.id,
                    event_timestamp=now - timedelta(hours=6),
                    source="Security.evtx",
                    event_type="authentication_failure",
                    severity="medium",
                    description="Multiple failed logon attempts against Administrator account (Brute-force)",
                    source_ip="185.220.101.5",
                    username="Administrator",
                    hostname="DC-01",
                    tags="auth_failure,windows",
                ),
                TimelineEvent(
                    case_id=case1.id,
                    event_timestamp=now - timedelta(hours=5, minutes=45),
                    source="Security.evtx",
                    event_type="authentication_success",
                    severity="high",
                    description="Successful RemoteInteractive logon (Type 10) for Administrator",
                    source_ip="185.220.101.5",
                    username="Administrator",
                    hostname="DC-01",
                    is_ioc_matched=True,
                    ioc_details="Matched Known Cobalt Strike C2 IP: 185.220.101.5",
                    tags="auth_success,rdp,ioc_matched",
                ),
                TimelineEvent(
                    case_id=case1.id,
                    event_timestamp=now - timedelta(hours=5, minutes=30),
                    source="Sysmon",
                    event_type="process_execution",
                    severity="critical",
                    description="PowerShell Encoded Command execution spawning stager",
                    process_name="powershell.exe",
                    command_line="powershell.exe -NoP -NonI -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
                    hostname="DC-01",
                    username="Administrator",
                    tags="powershell,encoded_command,t1059",
                ),
                TimelineEvent(
                    case_id=case1.id,
                    event_timestamp=now - timedelta(hours=4, minutes=15),
                    source="Sysmon",
                    event_type="privilege_escalation",
                    severity="critical",
                    description="LSASS memory dump executed via procdump.exe",
                    process_name="procdump.exe",
                    command_line="procdump.exe -ma lsass.exe lsass.dmp",
                    hostname="DC-01",
                    username="Administrator",
                    tags="lsass,credential_dumping,t1003",
                ),
                TimelineEvent(
                    case_id=case1.id,
                    event_timestamp=now - timedelta(hours=3, minutes=10),
                    source="Security.evtx",
                    event_type="defense_evasion",
                    severity="critical",
                    description="Security audit log was cleared by Administrator (EventID 1102)",
                    hostname="DC-01",
                    username="Administrator",
                    tags="log_cleared,defense_evasion,t1070",
                ),
            ]
            db.add_all(timeline_events)
            await db.commit()
            print("  [+] Generated Chronological Attack Timeline")

            # 5. Create Incident and Playbook Tasks
            inc = Incident(
                case_id=case1.id,
                incident_number="INC-2026-0001",
                title="Active Domain Controller Compromise & C2 Outbreak",
                description="Active adversary controlling DC-01 via Cobalt Strike C2 beacon. Immediate containment required.",
                severity="critical",
                status="active",
                phase="containment",
                containment_status="partially_contained",
                impact_level="critical",
                lead_responder_id=admin.id,
            )
            inc.tasks.append(IncidentTask(title="Isolate DC-01 from WAN & Non-essential VLANs", phase="containment", priority="critical", status="completed"))
            inc.tasks.append(IncidentTask(title="Reset Kerberos Ticket-Granting (krbtgt) Password Twice", phase="containment", priority="critical", status="in_progress"))
            inc.tasks.append(IncidentTask(title="Block 185.220.101.5 at Global Edge Perimeter", phase="containment", priority="high", status="completed"))
            inc.tasks.append(IncidentTask(title="Scan Internal Subnets for Lateral Movement", phase="eradication", priority="high", status="todo"))

            inc.notes.append(
                AnalystNote(
                    case_id=case1.id,
                    author_id=admin.id,
                    title="C2 Beaconing Analysis",
                    content="Observed jittered HTTPS beaconing to 185.220.101.5 every 45-60 seconds. Perimeter firewall rule 8092 successfully applied to block egress.",
                    is_pinned=True,
                    tags="c2,containment,firewall",
                )
            )
            db.add(inc)
            await db.commit()
            print("  [+] Created Incident Response Workspace & NIST Playbook Tasks")

        print("[+] FORENSIC-X Demo Data Seeding Completed Successfully!")


if __name__ == "__main__":
    asyncio.run(seed_demo())
