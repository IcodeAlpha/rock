"""
Process NSL-KDD credential attack data
"""
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / 'data/raw/credential_attacks'
PROCESSED_DIR = BASE_DIR / 'data/processed'

col_names = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','attack_type','difficulty'
]

print("Loading NSL-KDD...")
train = pd.read_csv(RAW_DIR / 'KDDTrain+.txt', header=None, names=col_names)
test = pd.read_csv(RAW_DIR / 'KDDTest+.txt', header=None, names=col_names)
combined = pd.concat([train, test], ignore_index=True)
combined = combined.drop(columns=['difficulty'])

print(f"Rows: {len(combined):,}")
print(f"Attack types:")
print(combined['attack_type'].value_counts().head(20))

# Map to categories
credential_attacks = ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop',
                      'warezmaster', 'warezclient', 'spy']
dos_attacks = ['neptune', 'smurf', 'pod', 'teardrop', 'back', 'land',
               'processtable', 'udpstorm', 'apache2', 'mailbomb']
probe_attacks = ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint']
r2l_attacks = ['guess_passwd', 'ftp_write', 'imap', 'phf', 'multihop',
               'warezmaster', 'warezclient', 'spy', 'xlock', 'xsnoop',
               'snmpguess', 'snmpgetattack', 'httptunnel', 'sendmail', 'named']
u2r_attacks = ['buffer_overflow', 'loadmodule', 'rootkit', 'perl',
               'sqlattack', 'xterm', 'ps']

def categorize(attack):
    if attack == 'normal':
        return 'Normal'
    elif attack in dos_attacks:
        return 'DoS'
    elif attack in probe_attacks:
        return 'Reconnaissance'
    elif attack in r2l_attacks:
        return 'Credential_Attack'
    elif attack in u2r_attacks:
        return 'Privilege_Escalation'
    else:
        return 'Other_Attack'

combined['attack_category'] = combined['attack_type'].apply(categorize)

print(f"\nAttack categories:")
print(combined['attack_category'].value_counts())

out = PROCESSED_DIR / 'credential_attacks.csv'
combined.to_csv(out, index=False)
print(f"\nSaved to: {out}")
print(f"Size: {out.stat().st_size / (1024*1024):.1f} MB")
print("Done!")