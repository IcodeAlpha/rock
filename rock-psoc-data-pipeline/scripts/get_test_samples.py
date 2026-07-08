import pandas as pd
import json
from pathlib import Path

RAW_DIR = Path('data/raw/unsw_nb15')

# Load from training set
train = pd.read_csv(RAW_DIR / 'UNSW_NB15_training-set.csv')
train['attack_cat'] = train['attack_cat'].str.strip()

# These are the exact feature names the model was trained on
# (from process_full_unsw.py output)
features = ['dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
            'Sload', 'Dload', 'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb',
            'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
            'Sjit', 'Djit', 'Sintpkt', 'Dintpkt', 'tcprtt', 'synack',
            'ackdat', 'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
            'is_ftp_login', 'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm',
            'ct_src_ ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm']

for attack in ['Normal', 'DoS', 'Reconnaissance', 'Backdoor', 'Exploits', 'Generic']:
    samples = train[train['attack_cat'] == attack]
    if len(samples) == 0:
        print(f"\n--- {attack} --- NOT FOUND")
        continue
    # Take a random sample not just the first one
    sample = samples.sample(1, random_state=42).iloc[0]
    data = {}
    for f in features:
        if f in sample.index:
            try:
                data[f] = round(float(sample[f]), 4)
            except:
                data[f] = 0.0
        else:
            data[f] = 0.0
    print(f"\n--- {attack} ---")
    print(json.dumps({"features": data}, indent=2))