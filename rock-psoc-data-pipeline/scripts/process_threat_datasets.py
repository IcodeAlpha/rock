"""
Process Threat Datasets — Ransomware, Malware, Credential Attacks
Mirrors the style of 2_process_nsl_kdd.py in this project.

Reads raw downloaded files, cleans them, engineers features, and writes
a unified JSON file to data/processed/ that train_threat_models.py consumes.

Usage:
    python scripts/process_threat_datasets.py
"""

import json
import random
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime, timedelta

# ─── Paths ───────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent.parent
RAW_DIR        = BASE_DIR / 'data' / 'raw'
PROCESSED_DIR  = BASE_DIR / 'data' / 'processed'
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ─── Helpers ─────────────────────────────────────────────────────────────────
def print_header(text):
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}")

def print_ok(text):   print(f"   ✅ {text}")
def print_warn(text): print(f"   ⚠️  {text}")
def print_err(text):  print(f"   ❌ {text}")
def print_info(text): print(f"   ℹ️  {text}")

random.seed(42)
np.random.seed(42)


# ─────────────────────────────────────────────────────────────────────────────
# PROCESSOR 1 — CIC-MalMem-2022  (Ransomware + Malware)
# ─────────────────────────────────────────────────────────────────────────────

# How the raw CIC-MalMem label maps to our dashboard threat categories
CICMALMEM_LABEL_MAP = {
    # Ransomware families
    'Ransomware.Maze':          'Ransomware',
    'Ransomware.Ryuk':          'Ransomware',
    'Ransomware.REvil':         'Ransomware',
    'Ransomware.Conti':         'Ransomware',
    'Ransomware.DarkSide':      'Ransomware',
    # Spyware
    'Spyware.Azorult':          'Malware - Spyware',
    'Spyware.Formbook':         'Malware - Spyware',
    # Trojans
    'Trojan.Emotet':            'Malware - Trojan',
    'Trojan.TrickBot':          'Malware - Trojan',
    'Trojan.AgentTesla':        'Malware - Trojan',
    # Benign
    'Benign':                   None,   # excluded
}

def severity_from_label(threat_type: str) -> str:
    if threat_type == 'Ransomware':
        return 'critical'
    if 'Trojan' in threat_type:
        return 'high'
    if 'Spyware' in threat_type:
        return 'medium'
    return 'low'

def process_cicmalmem() -> list[dict]:
    print_header("PROCESSING CIC-MalMem-2022 (Ransomware + Malware)")

    dest_dir = RAW_DIR / 'cicmalmem2022'
    csv_files = list(dest_dir.glob('*.csv')) if dest_dir.exists() else []

    if not csv_files:
        print_err("No CSV files found in data/raw/cicmalmem2022/")
        print_warn("Run download_threat_datasets.py first.")
        return []

    csv_path = csv_files[0]
    print_info(f"Reading: {csv_path.name}")

    try:
        df = pd.read_csv(csv_path)
    except Exception as e:
        print_err(f"Could not read {csv_path.name}: {e}")
        return []

    print_ok(f"Loaded {len(df):,} rows, {len(df.columns)} columns")

    # ── Find label column ─────────────────────────────────────────────────────
    label_col = next(
        (c for c in df.columns if c.lower() in ('label', 'class', 'category')),
        None
    )
    if not label_col:
        print_err("Could not identify label column. Columns: " + str(list(df.columns[:10])))
        return []

    print_info(f"Label column: '{label_col}'")
    print_info(f"Raw class distribution:\n{df[label_col].value_counts().to_string()}")

    # ── Drop benign rows ──────────────────────────────────────────────────────
    df = df[~df[label_col].str.lower().str.contains('benign', na=False)].copy()
    print_ok(f"After removing benign: {len(df):,} malicious records")

    # ── Map labels to threat types ────────────────────────────────────────────
    def map_label(raw: str) -> str | None:
        # Exact match first
        if raw in CICMALMEM_LABEL_MAP:
            return CICMALMEM_LABEL_MAP[raw]
        # Prefix match
        for key, val in CICMALMEM_LABEL_MAP.items():
            if raw.startswith(key.split('.')[0]):
                return val
        # Fallback heuristics
        r = raw.lower()
        if 'ransom' in r:  return 'Ransomware'
        if 'trojan' in r:  return 'Malware - Trojan'
        if 'spyware' in r: return 'Malware - Spyware'
        return 'Malware - General'

    df['threat_type'] = df[label_col].apply(map_label)
    df = df[df['threat_type'].notna()].copy()

    # ── Select numeric feature columns ────────────────────────────────────────
    feature_cols = [
        c for c in df.columns
        if c not in (label_col, 'threat_type')
        and df[c].dtype in (np.float64, np.int64, float, int)
    ]
    print_info(f"Using {len(feature_cols)} numeric features")

    # ── Sample if very large ──────────────────────────────────────────────────
    MAX_RECORDS = 2000
    if len(df) > MAX_RECORDS:
        df = df.sample(n=MAX_RECORDS, random_state=42)
        print_warn(f"Sampled down to {MAX_RECORDS} records for processing speed")

    # ── Build prediction objects (same schema as NSL-KDD pipeline) ────────────
    records = []
    for _, row in df.iterrows():
        threat_type = row['threat_type']
        severity    = severity_from_label(threat_type)

        base_prob = {'critical': 0.85, 'high': 0.75, 'medium': 0.65, 'low': 0.55}[severity]
        probability = float(np.clip(base_prob + random.uniform(-0.08, 0.08), 0.50, 0.99))

        indicators = {
            feat: (int(row[feat]) if pd.api.types.is_integer_dtype(df[feat].dtype)
                   else round(float(row[feat]), 4))
            for feat in feature_cols[:15]   # keep top 15 to stay concise
            if pd.notna(row[feat])
        }

        records.append({
            'threat_type':       threat_type,
            'severity':          severity,
            'probability':       round(probability, 2),
            'confidence_score':  0.84,
            'predicted_timeframe': random.choice(['1-2 days', '3-5 days', '5-7 days', '1-2 weeks']),
            'description': (
                f"Memory-forensic analysis detected {threat_type} indicators. "
                f"Pattern matches known {row[label_col]} behaviour."
            ),
            'indicators':        indicators,
            'source':            'CIC-MalMem-2022',
            'created_at':        (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        })

    print_ok(f"Built {len(records):,} prediction records")
    dist = pd.Series([r['threat_type'] for r in records]).value_counts()
    print_info(f"Threat distribution:\n{dist.to_string()}")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# PROCESSOR 2 — Credential / Brute-Force Attacks
# ─────────────────────────────────────────────────────────────────────────────

CREDENTIAL_LABEL_MAP = {
    # CIC-IDS2017 Tuesday labels
    'FTP-Patator':  'Credential Attack - Brute Force',
    'SSH-Patator':  'Credential Attack - Brute Force',
    'BENIGN':        None,
    'Benign':        None,
}

def process_credential_attacks() -> list[dict]:
    print_header("PROCESSING CREDENTIAL / BRUTE-FORCE DATASET")

    dest_dir = RAW_DIR / 'credential_attacks'
    csv_files = list(dest_dir.glob('*.csv')) if dest_dir.exists() else []

    if not csv_files:
        print_err("No CSV files found in data/raw/credential_attacks/")
        print_warn("Run download_threat_datasets.py first.")
        return []

    # Prefer Tuesday file (has brute-force), fall back to first available
    tuesday_files = [f for f in csv_files if 'tuesday' in f.name.lower()]
    csv_path = tuesday_files[0] if tuesday_files else csv_files[0]
    print_info(f"Reading: {csv_path.name}")

    try:
        df = pd.read_csv(csv_path, encoding='utf-8', low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(csv_path, encoding='latin-1', low_memory=False)
    except Exception as e:
        print_err(f"Could not read {csv_path.name}: {e}")
        return []

    # Strip column name whitespace (CIC-IDS2017 has leading spaces)
    df.columns = df.columns.str.strip()
    print_ok(f"Loaded {len(df):,} rows, {len(df.columns)} columns")

    # ── Find label column ─────────────────────────────────────────────────────
    label_col = next(
        (c for c in df.columns if 'label' in c.lower()),
        None
    )
    if not label_col:
        print_err("Could not find label column")
        return []

    print_info(f"Label column: '{label_col}'")
    print_info(f"Raw class distribution:\n{df[label_col].value_counts().to_string()}")

    # ── Filter to attack rows only ────────────────────────────────────────────
    attack_mask = ~df[label_col].str.strip().isin(['BENIGN', 'Benign', 'benign'])
    df = df[attack_mask].copy()
    print_ok(f"After removing benign: {len(df):,} attack records")

    # ── Map labels ────────────────────────────────────────────────────────────
    def map_label(raw: str) -> str:
        raw = raw.strip()
        if raw in CREDENTIAL_LABEL_MAP:
            return CREDENTIAL_LABEL_MAP[raw] or 'Credential Attack - Unknown'
        r = raw.lower()
        if 'ftp' in r or 'ssh' in r or 'patator' in r:
            return 'Credential Attack - Brute Force'
        if 'brute' in r:
            return 'Credential Attack - Brute Force'
        if 'credential' in r or 'stuffing' in r:
            return 'Credential Attack - Stuffing'
        return 'Credential Attack - Unknown'

    df['threat_type'] = df[label_col].apply(map_label)

    # ── Numeric features ──────────────────────────────────────────────────────
    numeric_cols = [
        c for c in df.columns
        if c not in (label_col, 'threat_type')
        and df[c].dtype in (np.float64, np.int64, float, int)
    ]

    # Replace inf values
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan).fillna(0)

    MAX_RECORDS = 2000
    if len(df) > MAX_RECORDS:
        df = df.sample(n=MAX_RECORDS, random_state=42)
        print_warn(f"Sampled down to {MAX_RECORDS} records")

    records = []
    for _, row in df.iterrows():
        threat_type = row['threat_type']

        # Credential attacks are always at least high severity
        severity = 'high'
        if row.get('Failed Login Count', row.get('failed_logins', 0)) > 5:
            severity = 'critical'

        base_prob = {'critical': 0.87, 'high': 0.76}[severity]
        probability = float(np.clip(base_prob + random.uniform(-0.08, 0.08), 0.50, 0.99))

        indicators = {
            col: round(float(row[col]), 4)
            for col in numeric_cols[:15]
            if pd.notna(row[col]) and row[col] != 0
        }

        records.append({
            'threat_type':       threat_type,
            'severity':          severity,
            'probability':       round(probability, 2),
            'confidence_score':  0.81,
            'predicted_timeframe': random.choice(['1-2 days', '3-5 days', '5-7 days']),
            'description': (
                f"Network flow analysis detected {threat_type} pattern. "
                f"Traffic signature matches known credential-attack tooling."
            ),
            'indicators':        indicators,
            'source':            'CIC-IDS2017 Credential Subset',
            'created_at':        (datetime.now() - timedelta(days=random.randint(0, 30))).isoformat()
        })

    print_ok(f"Built {len(records):,} prediction records")
    dist = pd.Series([r['threat_type'] for r in records]).value_counts()
    print_info(f"Threat distribution:\n{dist.to_string()}")
    return records


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  THREAT DATASET PROCESSOR")
    print("  Ransomware · Malware · Credential Attacks")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    all_records = []

    malware_records     = process_cicmalmem()
    credential_records  = process_credential_attacks()

    all_records.extend(malware_records)
    all_records.extend(credential_records)

    if not all_records:
        print_err("No records were processed. Check that datasets are downloaded.")
        return

    # ── Save combined JSON ────────────────────────────────────────────────────
    out_path = PROCESSED_DIR / 'threat_predictions.json'
    with open(out_path, 'w') as f:
        json.dump(all_records, f, indent=2)

    print_header("PROCESSING COMPLETE")
    print_ok(f"Total records: {len(all_records):,}")
    print_ok(f"Saved → {out_path.relative_to(BASE_DIR)}")

    overall_dist = pd.Series([r['threat_type'] for r in all_records]).value_counts()
    print_info(f"Overall threat distribution:\n{overall_dist.to_string()}")

    print()
    print("▶️   Next step: python scripts/train_threat_models.py")
    print()


if __name__ == '__main__':
    main()