#!/usr/bin/env python3
"""Generate a seeded ~300-alert / 24-hour SOC dataset.

Mandatory scenarios
-------------------
A  quiet_crown_jewel     4 Medium alerts, ~90 minutes, MUST be risk #1
B  ransomware_staging    6 Medium/High alerts, MUST be about risk #2
C  noisy_false_priority  ~120 Critical WAF/IDS alerts, MUST be legacy #1

Background noise is 160–180 isolated or tiny-burst alerts that must not
weld into a giant incident. scenario_id is for demo grading only.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from config import ALERTS_PATH, CMDB_PATH, DATA_DIR, IAM_PATH, RANDOM_SEED

DAY = datetime(2026, 3, 18, 0, 0, tzinfo=timezone.utc)

ASSETS = [
    {
        "host_id": "prd-app-02",
        "hostname": "prd-app-02.prod.internal",
        "ip_address": "10.20.8.22",
        "environment": "prod",
        "data_sensitivity": "confidential",
        "business_criticality": 4,
    },
    {
        "host_id": "prd-billing-db-01",
        "hostname": "prd-billing-db-01.prod.internal",
        "ip_address": "10.20.4.10",
        "environment": "prod",
        "data_sensitivity": "crown_jewel_pii_pci",
        "business_criticality": 5,
    },
    {
        "host_id": "dev-sandbox-04",
        "hostname": "dev-sandbox-04.sandbox.internal",
        "ip_address": "10.90.4.14",
        "environment": "sandbox",
        "data_sensitivity": "public",
        "business_criticality": 1,
    },
    {
        "host_id": "wrk-corp-14",
        "hostname": "wrk-corp-14.corp.internal",
        "ip_address": "10.30.22.14",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
    {
        "host_id": "prd-jump-01",
        "hostname": "prd-jump-01.prod.internal",
        "ip_address": "10.10.1.8",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 3,
    },
    {
        "host_id": "stg-api-02",
        "hostname": "stg-api-02.staging.internal",
        "ip_address": "10.40.2.16",
        "environment": "staging",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
    {
        "host_id": "dev-build-07",
        "hostname": "dev-build-07.dev.internal",
        "ip_address": "10.50.3.9",
        "environment": "dev",
        "data_sensitivity": "internal",
        "business_criticality": 1,
    },
    {
        "host_id": "wrk-helpdesk-03",
        "hostname": "wrk-helpdesk-03.corp.internal",
        "ip_address": "10.30.8.3",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
]

IDENTITIES = [
    {
        "user_id": "usr_svc_deploy",
        "department": "Platform Engineering",
        "privilege_tier": "service_account",
    },
    {
        "user_id": "usr_admin_root",
        "department": "IT Infrastructure",
        "privilege_tier": "tier_0_domain_admin",
    },
    {
        "user_id": "usr_jmartinez",
        "department": "Finance",
        "privilege_tier": "standard_user",
    },
    {
        "user_id": "usr_helpdesk_lee",
        "department": "IT Support",
        "privilege_tier": "standard_user",
    },
    {
        "user_id": "usr_cloud_reza",
        "department": "Platform Engineering",
        "privilege_tier": "tier_1_cloud_admin",
    },
    {
        "user_id": "usr_contractor_kim",
        "department": "Vendors",
        "privilege_tier": "standard_user",
    },
]

C_SCANNER_IP = "198.51.100.66"
A_UNUSUAL_IP = "193.32.162.88"
A_EXFIL_IP = "45.133.1.54"
APP_IP = "10.20.8.22"
BILLING_IP = "10.20.4.10"
SANDBOX_IP = "10.90.4.14"
WRK_IP = "10.30.22.14"


def _alert(
    *,
    alert_id: str,
    ts: datetime,
    product: str,
    rule: str,
    severity: str,
    confidence: float,
    fpr: float,
    tactic: str,
    technique: str,
    scenario_id: str,
    user_id: str | None = None,
    host_id: str | None = None,
    src_ip: str | None = None,
    dest_ip: str | None = None,
    process_hash: str | None = None,
) -> dict:
    return {
        "id": alert_id,
        "time": ts.isoformat(),
        "vendor": product,
        "signature": rule,
        "sev": severity,
        "confidence": round(confidence, 3),
        "fp_rate": round(fpr, 3),
        "tactic": tactic,
        "technique": technique,
        "scenario_id": scenario_id,
        "user_id": user_id,
        "host_id": host_id,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "process_hash": process_hash,
    }


def generate_quiet_crown_jewel(_rng: random.Random) -> list[dict]:
    """Scenario A: four Medium alerts over ~90 minutes."""
    t1 = DAY + timedelta(hours=2, minutes=10)
    t2 = DAY + timedelta(hours=2, minutes=38)
    t3 = DAY + timedelta(hours=3, minutes=5)
    t4 = DAY + timedelta(hours=3, minutes=40)
    return [
        _alert(
            alert_id="ALRT-A-001",
            ts=t1,
            product="Okta",
            rule="Anomalous VPN login from unusual ASN",
            severity="Medium",
            confidence=0.74,
            fpr=0.18,
            tactic="Initial Access",
            technique="T1078 - Valid Accounts",
            scenario_id="quiet_crown_jewel",
            user_id="usr_svc_deploy",
            host_id="prd-app-02",
            src_ip=f" {A_UNUSUAL_IP} ",
            dest_ip=APP_IP,
        ),
        _alert(
            alert_id="ALRT-A-002",
            ts=t2,
            product="CrowdStrike",
            rule="Suspicious PowerShell credential harvesting",
            severity="Medium",
            confidence=0.79,
            fpr=0.16,
            tactic="Credential Access",
            technique="T1003 - OS Credential Dumping",
            scenario_id="quiet_crown_jewel",
            user_id="usr_svc_deploy",
            host_id="prd-app-02",
            src_ip=APP_IP,
            process_hash="c41d2e90ab7712ff0091de44aa18c903",
        ),
        _alert(
            alert_id="ALRT-A-003",
            ts=t3,
            product="Darktrace",
            rule="SSH pivot from application host to billing database",
            severity="Medium",
            confidence=0.77,
            fpr=0.14,
            tactic="Lateral Movement",
            technique="T1021.004 - SSH",
            scenario_id="quiet_crown_jewel",
            user_id="usr_admin_root",
            host_id="prd-app-02",
            src_ip=APP_IP,
            dest_ip=BILLING_IP,
        ),
        _alert(
            alert_id="ALRT-A-004",
            ts=t4,
            product="Darktrace",
            rule="2.4 GB anomalous encrypted outbound transfer",
            severity="Medium",
            confidence=0.83,
            fpr=0.11,
            tactic="Exfiltration",
            technique="T1041 - Exfiltration Over C2 Channel",
            scenario_id="quiet_crown_jewel",
            user_id="usr_admin_root",
            host_id="prd-billing-db-01",
            src_ip=BILLING_IP,
            dest_ip=A_EXFIL_IP,
        ),
    ]


def generate_ransomware_staging(_rng: random.Random) -> list[dict]:
    """Scenario B: six-step staging toward Impact on a corp workstation."""
    times = [
        DAY + timedelta(hours=14, minutes=5),
        DAY + timedelta(hours=14, minutes=18),
        DAY + timedelta(hours=14, minutes=31),
        DAY + timedelta(hours=14, minutes=44),
        DAY + timedelta(hours=15, minutes=0),
        DAY + timedelta(hours=15, minutes=20),
    ]
    rows = [
        (
            "Okta",
            "Phishing-driven session from mailbox payload",
            "Medium",
            0.68,
            0.22,
            "Initial Access",
            "T1566.001 - Spearphishing Attachment",
        ),
        (
            "CrowdStrike",
            "User-launched payload execution",
            "Medium",
            0.71,
            0.20,
            "Execution",
            "T1204.002 - Malicious File",
        ),
        (
            "CrowdStrike",
            "PowerShell execution after phishing payload",
            "High",
            0.76,
            0.17,
            "Execution",
            "T1059.001 - PowerShell",
        ),
        (
            "CrowdStrike",
            "LSASS credential dumping",
            "High",
            0.82,
            0.13,
            "Credential Access",
            "T1003.001 - LSASS Memory",
        ),
        (
            "Darktrace",
            "SMB lateral scanning from workstation",
            "High",
            0.73,
            0.19,
            "Lateral Movement",
            "T1021.002 - SMB/Windows Admin Shares",
        ),
        (
            "CrowdStrike",
            "Shadow-copy deletion via vssadmin",
            "High",
            0.85,
            0.10,
            "Impact",
            "T1490 - Inhibit System Recovery",
        ),
    ]
    alerts = []
    for i, ((product, rule, sev, conf, fpr, tactic, tech), ts) in enumerate(
        zip(rows, times), start=1
    ):
        alerts.append(
            _alert(
                alert_id=f"ALRT-B-{i:03d}",
                ts=ts,
                product=product,
                rule=rule,
                severity=sev,
                confidence=conf,
                fpr=fpr,
                tactic=tactic,
                technique=tech,
                scenario_id="ransomware_staging",
                user_id="usr_jmartinez",
                host_id="wrk-corp-14",
                src_ip=WRK_IP,
                dest_ip="10.30.0.255" if "SMB" in rule else None,
                process_hash="e7a91c20bb4410de77aa9012cc44f018" if i >= 2 else None,
            )
        )
    return alerts


def generate_noisy_false_priority(rng: random.Random) -> list[dict]:
    """Scenario C: ~120 Critical WAF/IDS hits on a worthless sandbox."""
    family = [
        (
            "WAF",
            "WAF CVE-2024-21762 exploit attempt",
            "Initial Access",
            "T1190 - Exploit Public-Facing Application",
        ),
        (
            "IDS",
            "IDS CVE-2024-21762 payload detected",
            "Initial Access",
            "T1190 - Exploit Public-Facing Application",
        ),
        (
            "WAF",
            "WAF CVE-2024-21762 traversal variant",
            "Discovery",
            "T1083 - File and Directory Discovery",
        ),
    ]
    alerts = []
    n = 120
    start = DAY + timedelta(hours=8)
    for i in range(1, n + 1):
        product, rule, tactic, technique = family[i % len(family)]
        minutes = (i / n) * 210
        alerts.append(
            _alert(
                alert_id=f"ALRT-C-{i:04d}",
                ts=start + timedelta(minutes=minutes + rng.uniform(-0.3, 0.3)),
                product=product,
                rule=rule,
                severity="Critical",
                confidence=0.94,
                fpr=0.85,
                tactic=tactic,
                technique=technique,
                scenario_id="noisy_false_priority",
                host_id="dev-sandbox-04",
                src_ip=C_SCANNER_IP,
                dest_ip=SANDBOX_IP,
            )
        )
    return alerts


def generate_background_noise(rng: random.Random) -> list[dict]:
    """160–180 realistic isolations. Unique entities so they cannot weld."""
    alerts: list[dict] = []
    n = 0

    def next_id() -> str:
        nonlocal n
        n += 1
        return f"ALRT-N-{n:03d}"

    def at_hour(hour: float) -> datetime:
        return DAY + timedelta(hours=hour)

    # Failed logins: 10 tiny pairs, unique users, no shared IPs.
    for i in range(10):
        user = f"usr_noise_fail_{i:02d}"
        src = f"203.0.113.{10 + i}"
        for j in range(2):
            alerts.append(
                _alert(
                    alert_id=next_id(),
                    ts=at_hour(1.0 + i * 0.7) + timedelta(minutes=j * 2),
                    product="Okta",
                    rule="Failed interactive login",
                    severity="Low",
                    confidence=0.40,
                    fpr=0.80,
                    tactic="Credential Access",
                    technique="T1110 - Brute Force",
                    scenario_id="background_noise",
                    user_id=user,
                    src_ip=src,
                )
            )

    # Vulnerability scans: 8 clusters of 3, unique scanner + unique target.
    for i in range(8):
        src = f"192.0.2.{20 + i}"
        dest = f"10.71.{i}.10"
        host = f"wrk-noise-scan-{i:02d}"
        for j in range(3):
            alerts.append(
                _alert(
                    alert_id=next_id(),
                    ts=at_hour(4.0 + i * 0.4) + timedelta(minutes=j * 3),
                    product="Splunk",
                    rule="Authenticated vulnerability plugin hit",
                    severity="High",
                    confidence=0.86,
                    fpr=0.78,
                    tactic="Discovery",
                    technique="T1595 - Active Scanning",
                    scenario_id="background_noise",
                    host_id=host,
                    src_ip=src,
                    dest_ip=dest,
                )
            )

    # Isolated malware detections: 20 unique hosts.
    for i in range(20):
        alerts.append(
            _alert(
                alert_id=next_id(),
                ts=at_hour(6.0 + i * 0.25),
                product="CrowdStrike",
                rule="Unsigned binary in user temp",
                severity="Low",
                confidence=0.38,
                fpr=0.81,
                tactic="Execution",
                technique="T1204.002 - Malicious File",
                scenario_id="background_noise",
                host_id=f"wrk-noise-mal-{i:02d}",
                src_ip=f"10.72.{i}.20",
            )
        )

    # Routine administrative scripts: 16 unique admin sessions.
    for i in range(16):
        alerts.append(
            _alert(
                alert_id=next_id(),
                ts=at_hour(11.0 + i * 0.3),
                product="CrowdStrike",
                rule="Routine administrative PowerShell",
                severity="Low",
                confidence=0.35,
                fpr=0.77,
                tactic="Execution",
                technique="T1059.001 - PowerShell",
                scenario_id="background_noise",
                user_id=f"usr_noise_admin_{i:02d}",
                host_id=f"wrk-noise-adm-{i:02d}",
                src_ip=f"10.73.{i}.8",
            )
        )

    # WAF probes against non-sandbox marketing hosts: 15 pairs.
    for i in range(15):
        src = f"198.51.100.{80 + i}"
        dest = f"10.91.{i}.4"
        host = f"pub-noise-waf-{i:02d}"
        for j in range(2):
            alerts.append(
                _alert(
                    alert_id=next_id(),
                    ts=at_hour(16.0 + i * 0.15) + timedelta(minutes=j),
                    product="F5",
                    rule="Opportunistic WAF probe",
                    severity="Medium",
                    confidence=0.55,
                    fpr=0.84,
                    tactic="Initial Access",
                    technique="T1190 - Exploit Public-Facing Application",
                    scenario_id="background_noise",
                    host_id=host,
                    src_ip=src,
                    dest_ip=dest,
                )
            )

    # Brute-force bursts: 3 users × 8 attempts (dedup to 3 survivors).
    for i in range(3):
        user = f"usr_noise_brute_{i:02d}"
        src = f"203.0.113.{80 + i}"
        for j in range(8):
            alerts.append(
                _alert(
                    alert_id=next_id(),
                    ts=at_hour(18.0 + i) + timedelta(minutes=j),
                    product="Okta",
                    rule="Password-spray remnant",
                    severity="Low",
                    confidence=0.42,
                    fpr=0.83,
                    tactic="Credential Access",
                    technique="T1110.003 - Password Spraying",
                    scenario_id="background_noise",
                    user_id=user,
                    src_ip=src,
                )
            )

    # Benign PowerShell: 12 unique workstations.
    for i in range(12):
        alerts.append(
            _alert(
                alert_id=next_id(),
                ts=at_hour(12.5 + i * 0.2),
                product="CrowdStrike",
                rule="Benign signed PowerShell management script",
                severity="Low",
                confidence=0.33,
                fpr=0.82,
                tactic="Execution",
                technique="T1059.001 - PowerShell",
                scenario_id="background_noise",
                host_id=f"wrk-noise-ps-{i:02d}",
                src_ip=f"10.74.{i}.14",
            )
        )

    # Authentication anomalies: 12 unique users.
    for i in range(12):
        alerts.append(
            _alert(
                alert_id=next_id(),
                ts=at_hour(20.0 + i * 0.15),
                product="Okta",
                rule="Low-confidence authentication anomaly",
                severity="Low",
                confidence=0.36,
                fpr=0.76,
                tactic="Initial Access",
                technique="T1078 - Valid Accounts",
                scenario_id="background_noise",
                user_id=f"usr_noise_auth_{i:02d}",
                src_ip=f"198.51.100.{40 + i}",
            )
        )

    # Low-confidence network detections: 12 unique pairs.
    for i in range(12):
        alerts.append(
            _alert(
                alert_id=next_id(),
                ts=at_hour(21.0 + i * 0.15),
                product="Darktrace",
                rule="Low-confidence beacon-like traffic",
                severity="Low",
                confidence=0.28,
                fpr=0.86,
                    tactic="Discovery",
                technique="T1046 - Network Service Discovery",
                scenario_id="background_noise",
                host_id=f"wrk-noise-ndr-{i:02d}",
                src_ip=f"10.75.{i}.30",
                dest_ip=f"8.8.8.8",
            )
        )

    assert 160 <= len(alerts) <= 180, len(alerts)
    return alerts


def generate_dataset(seed: int = RANDOM_SEED) -> tuple[list[dict], list[dict], list[dict]]:
    rng = random.Random(seed)
    alerts: list[dict] = []
    alerts.extend(generate_quiet_crown_jewel(rng))
    alerts.extend(generate_ransomware_staging(rng))
    alerts.extend(generate_noisy_false_priority(rng))
    alerts.extend(generate_background_noise(rng))
    alerts.sort(key=lambda a: (a["time"], a["id"]))
    return ASSETS, IDENTITIES, alerts


def write_dataset(seed: int = RANDOM_SEED) -> dict[str, int]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    assets, identities, alerts = generate_dataset(seed)
    CMDB_PATH.write_text(json.dumps(assets, indent=2) + "\n", encoding="utf-8")
    IAM_PATH.write_text(json.dumps(identities, indent=2) + "\n", encoding="utf-8")
    with ALERTS_PATH.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert) + "\n")
    counts: dict[str, int] = {}
    for alert in alerts:
        sid = alert["scenario_id"]
        counts[sid] = counts.get(sid, 0) + 1
    span_h = (
        datetime.fromisoformat(alerts[-1]["time"]) - datetime.fromisoformat(alerts[0]["time"])
    ).total_seconds() / 3600.0
    return {
        "assets": len(assets),
        "identities": len(identities),
        "alerts": len(alerts),
        "span_hours": round(span_h, 2),
        **{f"scenario_{k}": v for k, v in sorted(counts.items())},
    }


def main() -> None:
    summary = write_dataset()
    print("Wrote synthetic SOC dataset")
    for key, value in summary.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
