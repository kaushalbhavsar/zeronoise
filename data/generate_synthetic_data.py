#!/usr/bin/env python3
"""Generate a seeded, offline SOC dataset that proves ranking inversion.

The dataset is built so a stealthy multi-stage breach against a crown-jewel
production system produces a handful of Medium alerts, while a noisy scanner
hammers a sandbox with hundreds of Critical alerts. The engine must rank the
breach first by risk and the scanner first by legacy SIEM logic.

scenario_id is written only so acceptance tests can label the demo. The
engine must never read it for correlation or scoring.
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

T0 = datetime(2026, 3, 18, 13, 5, tzinfo=timezone.utc)

ASSETS = [
    {
        "host_id": "host-pci-db-01",
        "hostname": "pci-db-01.prod.internal",
        "ip_address": "10.20.4.12",
        "environment": "prod",
        "data_sensitivity": "crown_jewel_pii_pci",
        "business_criticality": 5,
    },
    {
        "host_id": "host-fin-web-01",
        "hostname": "fin-web-01.prod.internal",
        "ip_address": "10.20.8.21",
        "environment": "prod",
        "data_sensitivity": "confidential",
        "business_criticality": 4,
    },
    {
        "host_id": "host-dc-01",
        "hostname": "dc-01.corp.internal",
        "ip_address": "10.10.0.11",
        "environment": "prod",
        "data_sensitivity": "confidential",
        "business_criticality": 5,
    },
    {
        "host_id": "host-hr-app-01",
        "hostname": "hr-app-01.prod.internal",
        "ip_address": "10.20.9.40",
        "environment": "prod",
        "data_sensitivity": "confidential",
        "business_criticality": 3,
    },
    {
        "host_id": "host-jump-01",
        "hostname": "jump-01.prod.internal",
        "ip_address": "10.10.1.8",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 4,
    },
    {
        "host_id": "host-stg-api-02",
        "hostname": "stg-api-02.staging.internal",
        "ip_address": "10.40.2.16",
        "environment": "staging",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
    {
        "host_id": "host-dev-build-03",
        "hostname": "dev-build-03.dev.internal",
        "ip_address": "10.50.3.9",
        "environment": "dev",
        "data_sensitivity": "internal",
        "business_criticality": 1,
    },
    {
        "host_id": "host-sandbox-web-07",
        "hostname": "sandbox-web-07.sandbox.internal",
        "ip_address": "10.90.1.77",
        "environment": "sandbox",
        "data_sensitivity": "public",
        "business_criticality": 1,
    },
    {
        "host_id": "host-sandbox-api-03",
        "hostname": "sandbox-api-03.sandbox.internal",
        "ip_address": "10.90.1.33",
        "environment": "sandbox",
        "data_sensitivity": "public",
        "business_criticality": 1,
    },
    {
        "host_id": "host-ws-maria",
        "hostname": "ws-maria-chen.corp.internal",
        "ip_address": "10.30.14.88",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
    {
        "host_id": "host-ws-admin",
        "hostname": "ws-da-okonkwo.corp.internal",
        "ip_address": "10.30.1.5",
        "environment": "prod",
        "data_sensitivity": "confidential",
        "business_criticality": 4,
    },
    {
        "host_id": "host-ws-hr",
        "hostname": "ws-priya-nair.corp.internal",
        "ip_address": "10.30.18.22",
        "environment": "prod",
        "data_sensitivity": "internal",
        "business_criticality": 2,
    },
]

IDENTITIES = [
    {
        "user_id": "u-maria-chen",
        "department": "Finance",
        "privilege_tier": "standard_user",
    },
    {
        "user_id": "u-da-okonkwo",
        "department": "IT Infrastructure",
        "privilege_tier": "tier_0_domain_admin",
    },
    {
        "user_id": "u-cloud-reza",
        "department": "Platform Engineering",
        "privilege_tier": "tier_1_cloud_admin",
    },
    {
        "user_id": "u-svc-backup",
        "department": "Platform Engineering",
        "privilege_tier": "service_account",
    },
    {
        "user_id": "u-priya-nair",
        "department": "Human Resources",
        "privilege_tier": "standard_user",
    },
    {
        "user_id": "u-helpdesk-lee",
        "department": "IT Support",
        "privilege_tier": "standard_user",
    },
    {
        "user_id": "u-contractor-kim",
        "department": "Vendors",
        "privilege_tier": "standard_user",
    },
]

PRODUCT_MAP = {
    "CrowdStrike": "EDR",
    "Okta": "IAM",
    "Darktrace": "NDR",
    "F5": "WAF",
    "Symantec DLP": "DLP",
    "Splunk": "SIEM",
}

SCANNER_RULES = [
    (
        "WAF SQLi signature match",
        "F5",
        "Initial Access",
        "T1190 - Exploit Public-Facing Application",
    ),
    (
        "WAF XSS probe blocked",
        "F5",
        "Initial Access",
        "T1190 - Exploit Public-Facing Application",
    ),
    (
        "NDR mass port scan",
        "Darktrace",
        "Discovery",
        "T1046 - Network Service Discovery",
    ),
    (
        "SIEM CVE-2024-21762 exploit attempt",
        "Splunk",
        "Initial Access",
        "T1190 - Exploit Public-Facing Application",
    ),
    (
        "WAF directory traversal",
        "F5",
        "Discovery",
        "T1083 - File and Directory Discovery",
    ),
]


def _alert(
    rng: random.Random,
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
    # Intentionally messy vendor-shaped records so the normalizer has work.
    record: dict = {
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
    return record


def _jitter(rng: random.Random, minutes: float, spread: float = 2.0) -> timedelta:
    return timedelta(minutes=minutes + rng.uniform(-spread, spread))


def generate_true_breach(rng: random.Random) -> list[dict]:
    """Few Medium alerts spanning identity → creds → lateral → exfil."""
    alerts: list[dict] = []
    hash_beacon = "a7f3c91e0b2d44aa88c1e6d0f5b9a312"
    hash_lsass = "c41d2e90ab7712ff0091de44aa18c903"
    ext_ip = "185.243.112.44"
    workstation = "10.30.14.88"
    fin_web = "10.20.8.21"
    pci_db = "10.20.4.12"

    sequence = [
        (0, "Okta", "Impossible travel / new ASN login", "Medium", 0.71, 0.22,
         "Initial Access", "T1078 - Valid Accounts",
         "u-maria-chen", "host-ws-maria", "203.0.113.19", None, None),
        (8, "Okta", "MFA prompt accepted from unmanaged device", "Medium", 0.64, 0.28,
         "Initial Access", "T1078.004 - Cloud Accounts",
         "u-maria-chen", "host-ws-maria", "203.0.113.19", None, None),
        (18, "CrowdStrike", "Suspicious encoded PowerShell", "Medium", 0.69, 0.25,
         "Execution", "T1059.001 - PowerShell",
         "u-maria-chen", "host-ws-maria", workstation, None, hash_beacon),
        (27, "CrowdStrike", "LSASS memory access from non-AV process", "Medium", 0.78, 0.18,
         "Credential Access", "T1003.001 - LSASS Memory",
         "u-maria-chen", "host-ws-maria", workstation, None, hash_lsass),
        (36, "Okta", "Privileged group membership change", "Medium", 0.73, 0.16,
         "Privilege Escalation", "T1098 - Account Manipulation",
         "u-maria-chen", None, "203.0.113.19", None, None),
        (44, "CrowdStrike", "Scheduled task created for persistence", "Low", 0.61, 0.30,
         "Persistence", "T1053.005 - Scheduled Task",
         "u-maria-chen", "host-ws-maria", workstation, None, hash_beacon),
        (52, "Darktrace", "Unusual SMB to finance application", "Medium", 0.67, 0.21,
         "Lateral Movement", "T1021.002 - SMB/Windows Admin Shares",
         "u-maria-chen", "host-fin-web-01", workstation, fin_web, None),
        (61, "CrowdStrike", "Remote service execution on fin-web-01", "Medium", 0.70, 0.20,
         "Lateral Movement", "T1021.001 - Remote Desktop Protocol",
         "u-maria-chen", "host-fin-web-01", workstation, fin_web, hash_beacon),
        (70, "CrowdStrike", "Discovery commands on production app host", "Low", 0.58, 0.32,
         "Discovery", "T1087 - Account Discovery",
         "u-maria-chen", "host-fin-web-01", fin_web, None, None),
        (78, "Darktrace", "East-west connection to PCI database", "Medium", 0.76, 0.14,
         "Lateral Movement", "T1021 - Remote Services",
         "u-maria-chen", "host-pci-db-01", fin_web, pci_db, None),
        (86, "Symantec DLP", "Bulk PCI record query from application account", "Medium", 0.74, 0.17,
         "Collection", "T1213 - Data from Information Repositories",
         "u-maria-chen", "host-pci-db-01", fin_web, pci_db, None),
        (94, "Splunk", "After-hours access to crown-jewel datastore", "Medium", 0.66, 0.24,
         "Collection", "T1005 - Data from Local System",
         "u-maria-chen", "host-pci-db-01", fin_web, pci_db, None),
        (103, "Darktrace", "Large outbound transfer to rare ASN", "Medium", 0.81, 0.12,
         "Exfiltration", "T1041 - Exfiltration Over C2 Channel",
         "u-maria-chen", "host-pci-db-01", pci_db, ext_ip, None),
        (111, "Symantec DLP", "Regulated data staged to external destination", "Medium", 0.79, 0.13,
         "Exfiltration", "T1567 - Exfiltration Over Web Service",
         "u-maria-chen", "host-pci-db-01", pci_db, ext_ip, None),
    ]

    for i, row in enumerate(sequence, start=1):
        mins, product, rule, sev, conf, fpr, tactic, tech, user, host, src, dest, phash = row
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-BREACH-{i:03d}",
                ts=T0 + _jitter(rng, mins, 1.2),
                product=product,
                rule=rule,
                severity=sev,
                confidence=conf,
                fpr=fpr,
                tactic=tactic,
                technique=tech,
                scenario_id="true_breach",
                user_id=user,
                host_id=host,
                src_ip=src,
                dest_ip=dest,
                process_hash=phash,
            )
        )
    return alerts


def generate_noisy_scanner(rng: random.Random) -> list[dict]:
    """Hundreds of Critical alerts against an irrelevant sandbox."""
    alerts: list[dict] = []
    scanner_ip = "198.51.100.66"
    dest_ip = "10.90.1.77"
    n = 280
    for i in range(1, n + 1):
        rule, product, tactic, technique = SCANNER_RULES[i % len(SCANNER_RULES)]
        minutes = (i / n) * 95
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-SCAN-{i:04d}",
                ts=T0 + timedelta(minutes=minutes + rng.uniform(-0.4, 0.4)),
                product=product,
                rule=rule,
                severity="Critical",
                confidence=0.93,
                fpr=0.78,
                tactic=tactic,
                technique=technique,
                scenario_id="noisy_scanner",
                host_id="host-sandbox-web-07",
                src_ip=scanner_ip,
                dest_ip=dest_ip,
            )
        )
    return alerts


def generate_staging_scan(rng: random.Random) -> list[dict]:
    alerts: list[dict] = []
    dest_ip = "10.40.2.16"
    for i in range(1, 72):
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-STG-{i:03d}",
                ts=T0 + timedelta(minutes=5 + i * 0.7 + rng.uniform(-0.2, 0.2)),
                product="Splunk",
                rule="Nessus plugin hit on staging API",
                severity="High",
                confidence=0.88,
                fpr=0.71,
                tactic="Discovery",
                technique="T1595 - Active Scanning",
                scenario_id="staging_vuln_scan",
                host_id="host-stg-api-02",
                src_ip="192.0.2.15",
                dest_ip=dest_ip,
            )
        )
    return alerts


def generate_privileged_anomaly(rng: random.Random) -> list[dict]:
    """Domain-admin oddity without a completed kill chain."""
    rows = [
        (12, "Okta", "Domain admin login from new country", "High", 0.77, 0.19,
         "Initial Access", "T1078.002 - Domain Accounts",
         "u-da-okonkwo", "host-ws-admin", "41.86.22.10", None),
        (19, "CrowdStrike", "Admin workstation unusual process tree", "Medium", 0.62, 0.27,
         "Execution", "T1059 - Command and Scripting Interpreter",
         "u-da-okonkwo", "host-ws-admin", "10.30.1.5", None),
        (31, "Okta", "Privileged session without ticket justification", "Medium", 0.58, 0.31,
         "Privilege Escalation", "T1078.002 - Domain Accounts",
         "u-da-okonkwo", "host-dc-01", "10.30.1.5", "10.10.0.11"),
        (40, "Darktrace", "Admin host queried additional DCs", "Low", 0.54, 0.36,
         "Discovery", "T1018 - Remote System Discovery",
         "u-da-okonkwo", "host-dc-01", "10.30.1.5", "10.10.0.11"),
    ]
    alerts = []
    for i, row in enumerate(rows, start=1):
        mins, product, rule, sev, conf, fpr, tactic, tech, user, host, src, dest = row
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-PRIV-{i:03d}",
                ts=T0 + _jitter(rng, mins, 1.0),
                product=product,
                rule=rule,
                severity=sev,
                confidence=conf,
                fpr=fpr,
                tactic=tactic,
                technique=tech,
                scenario_id="privileged_anomaly",
                user_id=user,
                host_id=host,
                src_ip=src,
                dest_ip=dest,
            )
        )
    return alerts


def generate_insider_dlp(rng: random.Random) -> list[dict]:
    rows = [
        (22, "Symantec DLP", "HR export to personal USB", "Medium", 0.72, 0.20,
         "Collection", "T1052.001 - Exfiltration over USB",
         "u-priya-nair", "host-ws-hr", "10.30.18.22", None),
        (29, "Symantec DLP", "Confidential roster emailed externally", "Medium", 0.69, 0.23,
         "Exfiltration", "T1048 - Exfiltration Over Alternative Protocol",
         "u-priya-nair", "host-ws-hr", "10.30.18.22", "8.8.8.8"),
        (37, "Splunk", "After-hours HR application access", "Low", 0.51, 0.34,
         "Collection", "T1213 - Data from Information Repositories",
         "u-priya-nair", "host-hr-app-01", "10.30.18.22", "10.20.9.40"),
        (48, "Darktrace", "Unusual volume from HR workstation", "Medium", 0.63, 0.26,
         "Exfiltration", "T1041 - Exfiltration Over C2 Channel",
         "u-priya-nair", "host-ws-hr", "10.30.18.22", "198.51.100.20"),
    ]
    alerts = []
    for i, row in enumerate(rows, start=1):
        mins, product, rule, sev, conf, fpr, tactic, tech, user, host, src, dest = row
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-INS-{i:03d}",
                ts=T0 + _jitter(rng, mins, 1.0),
                product=product,
                rule=rule,
                severity=sev,
                confidence=conf,
                fpr=fpr,
                tactic=tactic,
                technique=tech,
                scenario_id="insider_dlp",
                user_id=user,
                host_id=host,
                src_ip=src,
                dest_ip=dest,
            )
        )
    return alerts


def generate_isolated_noise(rng: random.Random) -> list[dict]:
    templates = [
        ("CrowdStrike", "Unsigned binary in user temp", "Low", 0.44, 0.55,
         "Execution", "T1204 - User Execution",
         "u-helpdesk-lee", "host-dev-build-03", "10.50.3.9", None),
        ("Okta", "Single failed password spray remnant", "Low", 0.40, 0.62,
         "Credential Access", "T1110 - Brute Force",
         "u-contractor-kim", None, "203.0.113.80", None),
        ("F5", "One-off 404 flood from crawler", "Low", 0.38, 0.70,
         "Discovery", "T1595 - Active Scanning",
         None, "host-sandbox-api-03", "203.0.113.90", "10.90.1.33"),
        ("Splunk", "Expired service account login", "Medium", 0.50, 0.41,
         "Initial Access", "T1078.003 - Local Accounts",
         "u-svc-backup", "host-jump-01", "10.10.1.8", None),
        ("CrowdStrike", "Browser crash dump false positive", "Low", 0.33, 0.74,
         "Execution", "T1204.002 - Malicious File",
         "u-helpdesk-lee", "host-dev-build-03", "10.50.3.9", None),
    ]
    alerts = []
    for i in range(1, 36):
        product, rule, sev, conf, fpr, tactic, tech, user, host, src, dest = templates[i % len(templates)]
        alerts.append(
            _alert(
                rng,
                alert_id=f"ALRT-NOISE-{i:03d}",
                ts=T0 + timedelta(minutes=rng.uniform(0, 140)),
                product=product,
                rule=f"{rule} #{i}",
                severity=sev,
                confidence=conf,
                fpr=fpr,
                tactic=tactic,
                technique=tech,
                scenario_id="isolated_noise",
                user_id=user,
                host_id=host,
                src_ip=src,
                dest_ip=dest,
            )
        )
    return alerts


def generate_dataset(seed: int = RANDOM_SEED) -> tuple[list[dict], list[dict], list[dict]]:
    rng = random.Random(seed)
    alerts = []
    alerts.extend(generate_true_breach(rng))
    alerts.extend(generate_noisy_scanner(rng))
    alerts.extend(generate_staging_scan(rng))
    alerts.extend(generate_privileged_anomaly(rng))
    alerts.extend(generate_insider_dlp(rng))
    alerts.extend(generate_isolated_noise(rng))
    alerts.sort(key=lambda a: a["time"])
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
    return {
        "assets": len(assets),
        "identities": len(identities),
        "alerts": len(alerts),
        **{f"scenario_{k}": v for k, v in sorted(counts.items())},
    }


def main() -> None:
    summary = write_dataset()
    print("Wrote synthetic SOC dataset")
    for key, value in summary.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    main()
