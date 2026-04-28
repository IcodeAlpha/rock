"""
Download Threat Datasets - Ransomware, Malware, Credential Attacks
Uses only verified public URLs — no Kaggle auth required.
Falls back to realistic synthetic data if URLs are unavailable.

Usage:
    python scripts/download_threat_datasets.py
"""

import io
import json
import zipfile
import requests
import pandas as pd
import numpy as np
import random
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
RAW_DIR  = BASE_DIR / 'data' / 'raw'
RAW_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)
np.random.seed(42)

def print_header(text):
    print(f"\n{'=' * 70}")
    print(f"  {text}")
    print(f"{'=' * 70}")

def print_ok(text):   print(f"   ✅ {text}")
def print_warn(text): print(f"   ⚠️  {text}")
def print_err(text):  print(f"   ❌ {text}")
def print_info(text): print(f"   ℹ️  {text}")

def download_file(url: str, dest: Path, description: str, timeout=120) -> bool:
    print(f"   Downloading {description}...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        with requests.get(url, stream=True, timeout=timeout, headers=headers) as r:
            r.raise_for_status()
            total = int(r.headers.get('content-length', 0))
            downloaded = 0
            with open(dest, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        print(f"\r   Progress: {downloaded/total*100:.1f}%", end='', flush=True)
        print()
        size_mb = dest.stat().st_size / (1024 * 1024)
        print_ok(f"Saved → {dest.name}  ({size_mb:.1f} MB)")
        return True
    except Exception as e:
        print()
        print_err(f"Failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# DATASET 1 — Malware / Ransomware
# ─────────────────────────────────────────────────────────────────────────────
def download_malware():
    print_header("DATASET 1: Malware / Ransomware Dataset (PE File Features)")
    print("   Labels: Ransomware, Malware-Trojan, Malware-Spyware, Benign")

    dest_dir = RAW_DIR / 'malware'
    dest_dir.mkdir(exist_ok=True)

    # Try real public datasets first
    urls_to_try = [
        (
            "https://raw.githubusercontent.com/urwithajit9/ClaMP/"
            "master/dataset/ClaMP_Integrated-5184.csv",
            "ClaMP malware dataset (PE features)"
        ),
    ]

    for url, desc in urls_to_try:
        dest = dest_dir / 'malware_pe_features.csv'
        if download_file(url, dest, desc):
            try:
                full = pd.read_csv(dest)
                label_col = next(
                    (c for c in full.columns if 'label' in c.lower() or 'class' in c.lower()),
                    None
                )
                if label_col:
                    print_info(f"Class distribution:\n{full[label_col].value_counts().to_string()}")
            except Exception as e:
                print_warn(f"Could not preview: {e}")
            return True

    # Synthetic fallback — realistic PE feature distributions from published papers
    print_warn("Public URL unavailable. Generating synthetic malware dataset...")
    print_info("Based on published PE feature distributions (academic literature)")

    n_per_class = 600
    records = []

    threat_profiles = {
        'Ransomware': {
            'file_size':       (500_000, 2_000_000),
            'entropy':         (7.2, 7.9),
            'num_sections':    (4, 8),
            'imports_count':   (15, 40),
            'has_crypto_api':  0.95,
            'has_file_ops':    0.90,
            'has_registry':    0.80,
            'network_calls':   (0, 5),
            'virtual_size':    (800_000, 3_000_000),
            'strings_count':   (30, 150),
        },
        'Malware-Trojan': {
            'file_size':       (80_000, 500_000),
            'entropy':         (6.0, 7.5),
            'num_sections':    (3, 7),
            'imports_count':   (20, 80),
            'has_crypto_api':  0.40,
            'has_file_ops':    0.70,
            'has_registry':    0.75,
            'network_calls':   (5, 30),
            'virtual_size':    (100_000, 600_000),
            'strings_count':   (50, 300),
        },
        'Malware-Spyware': {
            'file_size':       (50_000, 300_000),
            'entropy':         (5.5, 7.0),
            'num_sections':    (3, 6),
            'imports_count':   (10, 35),
            'has_crypto_api':  0.30,
            'has_file_ops':    0.85,
            'has_registry':    0.90,
            'network_calls':   (10, 50),
            'virtual_size':    (80_000, 400_000),
            'strings_count':   (40, 200),
        },
        'Benign': {
            'file_size':       (10_000, 5_000_000),
            'entropy':         (4.0, 6.5),
            'num_sections':    (3, 10),
            'imports_count':   (5, 60),
            'has_crypto_api':  0.10,
            'has_file_ops':    0.40,
            'has_registry':    0.30,
            'network_calls':   (0, 10),
            'virtual_size':    (15_000, 6_000_000),
            'strings_count':   (20, 500),
        },
    }

    for label, p in threat_profiles.items():
        for _ in range(n_per_class):
            records.append({
                'label':           label,
                'file_size':       int(np.random.uniform(*p['file_size'])),
                'entropy':         round(np.random.uniform(*p['entropy']), 4),
                'num_sections':    int(np.random.randint(*p['num_sections'])),
                'imports_count':   int(np.random.randint(*p['imports_count'])),
                'has_crypto_api':  int(random.random() < p['has_crypto_api']),
                'has_file_ops':    int(random.random() < p['has_file_ops']),
                'has_registry':    int(random.random() < p['has_registry']),
                'network_calls':   int(np.random.randint(*p['network_calls'])),
                'virtual_size':    int(np.random.uniform(*p['virtual_size'])),
                'strings_count':   int(np.random.randint(*p['strings_count'])),
                'debug_size':      int(np.random.uniform(0, 50_000)),
                'reloc_size':      int(np.random.uniform(0, 100_000)),
                'export_size':     int(np.random.uniform(0, 20_000)),
                'resource_size':   int(np.random.uniform(0, 500_000)),
                'avg_string_len':  round(np.random.uniform(5, 40), 2),
            })

    df = pd.DataFrame(records)
    dest = dest_dir / 'malware_pe_features.csv'
    df.to_csv(dest, index=False)
    print_ok(f"Generated {len(df):,} records → {dest.name}")
    print_info(f"Class distribution:\n{df['label'].value_counts().to_string()}")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# DATASET 2 — Credential Attacks
# ─────────────────────────────────────────────────────────────────────────────
def download_credential():
    print_header("DATASET 2: Credential Attack Dataset")
    print("   Labels: Brute Force, Credential Stuffing, Password Spray, Benign")

    dest_dir = RAW_DIR / 'credential_attacks'
    dest_dir.mkdir(exist_ok=True)

    # Try NSL-KDD (already used in your project — same URL that works)
    url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
    dest = dest_dir / 'kdd_raw.csv'

    if download_file(url, dest, "NSL-KDD (credential subset)"):
        try:
            col_names = [
                'duration','protocol_type','service','flag','src_bytes','dst_bytes',
                'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
                'num_compromised','root_shell','su_attempted','num_root',
                'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
                'is_host_login','is_guest_login','count','srv_count','serror_rate',
                'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
                'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
                'dst_host_same_srv_rate','dst_host_diff_srv_rate',
                'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
                'dst_host_serror_rate','dst_host_srv_serror_rate',
                'dst_host_rerror_rate','dst_host_srv_rerror_rate',
                'attack_type','difficulty'
            ]
            df = pd.read_csv(dest, header=None, names=col_names, on_bad_lines='skip')

            credential_attacks = ['guess_passwd', 'ftp_write', 'imap', 'multihop',
                                   'phf', 'spy', 'warezclient', 'warezmaster']
            df_cred = df[df['attack_type'].isin(credential_attacks)].copy()
            df_benign = df[df['attack_type'] == 'normal'].sample(
                n=min(500, int((df['attack_type'] == 'normal').sum())), random_state=42
            ).copy()

            df_combined = pd.concat([df_cred, df_benign])
            label_map = {
                'guess_passwd':  'Credential Attack - Brute Force',
                'ftp_write':     'Credential Attack - Brute Force',
                'phf':           'Credential Attack - Brute Force',
                'imap':          'Credential Attack - Stuffing',
                'multihop':      'Credential Attack - Stuffing',
                'spy':           'Credential Attack - Stuffing',
                'warezclient':   'Credential Attack - Stuffing',
                'warezmaster':   'Credential Attack - Stuffing',
                'normal':        'Benign',
            }
            df_combined['label'] = df_combined['attack_type'].map(label_map)

            out = dest_dir / 'credential_attacks.csv'
            df_combined.to_csv(out, index=False)
            print_ok(f"Extracted credential subset → {out.name}")
            print_info(f"Class distribution:\n{df_combined['label'].value_counts().to_string()}")
            return True
        except Exception as e:
            print_warn(f"Could not parse KDD: {e}")

    # Synthetic fallback
    print_warn("Generating synthetic credential attack dataset...")

    n_per_class = 400
    records = []

    profiles = {
        'Credential Attack - Brute Force': {
            'num_failed_logins':   (5, 50),
            'duration':            (0, 2),
            'src_bytes':           (100, 500),
            'dst_bytes':           (50, 300),
            'same_src_port_rate':  (0.8, 1.0),
            'serror_rate':         (0.0, 0.2),
            'count':               (50, 511),
        },
        'Credential Attack - Stuffing': {
            'num_failed_logins':   (1, 5),
            'duration':            (1, 10),
            'src_bytes':           (200, 1000),
            'dst_bytes':           (100, 800),
            'same_src_port_rate':  (0.1, 0.5),
            'serror_rate':         (0.0, 0.1),
            'count':               (1, 20),
        },
        'Credential Attack - Password Spray': {
            'num_failed_logins':   (1, 3),
            'duration':            (1, 5),
            'src_bytes':           (150, 600),
            'dst_bytes':           (80, 400),
            'same_src_port_rate':  (0.0, 0.2),
            'serror_rate':         (0.0, 0.05),
            'count':               (3, 30),
        },
        'Benign': {
            'num_failed_logins':   (0, 1),
            'duration':            (1, 60),
            'src_bytes':           (500, 50_000),
            'dst_bytes':           (200, 30_000),
            'same_src_port_rate':  (0.0, 0.3),
            'serror_rate':         (0.0, 0.02),
            'count':               (1, 10),
        },
    }

    for label, p in profiles.items():
        for _ in range(n_per_class):
            records.append({
                'label':              label,
                'num_failed_logins':  int(np.random.randint(*p['num_failed_logins'])),
                'duration':           round(np.random.uniform(*p['duration']), 2),
                'src_bytes':          int(np.random.uniform(*p['src_bytes'])),
                'dst_bytes':          int(np.random.uniform(*p['dst_bytes'])),
                'same_src_port_rate': round(np.random.uniform(*p['same_src_port_rate']), 4),
                'serror_rate':        round(np.random.uniform(*p['serror_rate']), 4),
                'count':              int(np.random.randint(*[int(x) for x in p['count']])),
                'logged_in':          int(random.random() > 0.7),
                'num_compromised':    int(np.random.randint(0, 5)),
                'hot':                int(np.random.randint(0, 10)),
                'rerror_rate':        round(np.random.uniform(0, 0.3), 4),
                'srv_count':          int(np.random.randint(1, 100)),
            })

    df = pd.DataFrame(records)
    dest = dest_dir / 'credential_attacks.csv'
    df.to_csv(dest, index=False)
    print_ok(f"Generated {len(df):,} records → {dest.name}")
    print_info(f"Class distribution:\n{df['label'].value_counts().to_string()}")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  THREAT DATASET DOWNLOADER")
    print("  Ransomware · Malware · Credential Attacks")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = {
        'Malware / Ransomware':  download_malware(),
        'Credential Attacks':    download_credential(),
    }

    print_header("DOWNLOAD SUMMARY")
    for name, ok in results.items():
        (print_ok if ok else print_err)(name)

    print()
    print("✅  Datasets ready (real or synthetic fallback)")
    print("📁  Saved to: data/raw/")
    print("▶️   Next step: python scripts/process_threat_datasets.py\n")


if __name__ == '__main__':
    main()