"""
Fetch CVE data from NVD (National Vulnerability Database) free API
No API key required for basic access
"""
import requests
import json
import pandas as pd
import time
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
RAW_DIR = BASE_DIR / 'data/raw'
PROCESSED_DIR = BASE_DIR / 'data/processed'
RAW_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("📥 FETCHING NVD CVE DATA")
print("=" * 70)

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

all_cves = []
start_index = 0
results_per_page = 2000
total_fetched = 0
max_cves = 20000  # fetch 20K CVEs

print(f"\nFetching up to {max_cves:,} CVEs from NVD API...")
print("(Rate limited to 1 request per 6 seconds without API key)\n")

while total_fetched < max_cves:
    params = {
        'startIndex': start_index,
        'resultsPerPage': results_per_page,
    }

    try:
        print(f"  Fetching batch {start_index} to {start_index + results_per_page}...")
        r = requests.get(BASE_URL, params=params, timeout=30)

        if r.status_code == 200:
            data = r.json()
            vulnerabilities = data.get('vulnerabilities', [])

            if not vulnerabilities:
                print("  No more CVEs to fetch.")
                break

            for item in vulnerabilities:
                cve = item.get('cve', {})
                cve_id = cve.get('id', '')
                published = cve.get('published', '')
                modified = cve.get('lastModified', '')
                status = cve.get('vulnStatus', '')

                # Get CVSS scores
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
                cvss_v2 = metrics.get('cvssMetricV2', [])

                base_score_v3 = None
                severity_v3 = None
                attack_vector = None
                attack_complexity = None
                privileges_required = None
                user_interaction = None
                scope = None
                confidentiality = None
                integrity = None
                availability = None

                if cvss_v3:
                    cvss_data = cvss_v3[0].get('cvssData', {})
                    base_score_v3 = cvss_data.get('baseScore')
                    severity_v3 = cvss_data.get('baseSeverity')
                    attack_vector = cvss_data.get('attackVector')
                    attack_complexity = cvss_data.get('attackComplexity')
                    privileges_required = cvss_data.get('privilegesRequired')
                    user_interaction = cvss_data.get('userInteraction')
                    scope = cvss_data.get('scope')
                    confidentiality = cvss_data.get('confidentialityImpact')
                    integrity = cvss_data.get('integrityImpact')
                    availability = cvss_data.get('availabilityImpact')

                base_score_v2 = None
                if cvss_v2 and base_score_v3 is None:
                    base_score_v2 = cvss_v2[0].get('cvssData', {}).get('baseScore')

                # Get description
                descriptions = cve.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')

                # Get CWE
                weaknesses = cve.get('weaknesses', [])
                cwe = ''
                if weaknesses:
                    cwe_desc = weaknesses[0].get('description', [])
                    cwe = cwe_desc[0].get('value', '') if cwe_desc else ''

                all_cves.append({
                    'cve_id': cve_id,
                    'published': published,
                    'modified': modified,
                    'status': status,
                    'base_score_v3': base_score_v3,
                    'base_score_v2': base_score_v2,
                    'severity': severity_v3,
                    'attack_vector': attack_vector,
                    'attack_complexity': attack_complexity,
                    'privileges_required': privileges_required,
                    'user_interaction': user_interaction,
                    'scope': scope,
                    'confidentiality_impact': confidentiality,
                    'integrity_impact': integrity,
                    'availability_impact': availability,
                    'cwe': cwe,
                    'description_length': len(description),
                })

            fetched = len(vulnerabilities)
            total_fetched += fetched
            start_index += results_per_page

            print(f"  ✅ Fetched {fetched} CVEs (total: {total_fetched:,})")

            if fetched < results_per_page:
                print("  Reached end of dataset.")
                break

            # Rate limit
            time.sleep(6)

        elif r.status_code == 429:
            print("  ⚠️  Rate limited — waiting 30 seconds...")
            time.sleep(30)
        else:
            print(f"  ❌ Error: {r.status_code}")
            break

    except Exception as e:
        print(f"  ❌ Exception: {e}")
        break

print(f"\n✅ Total CVEs fetched: {len(all_cves):,}")

# Save raw
df = pd.DataFrame(all_cves)
print(f"\n📊 Dataset Info:")
print(f"   Rows: {len(df):,}")
print(f"   Columns: {list(df.columns)}")
print(f"\n   Severity distribution:")
print(df['severity'].value_counts())
print(f"\n   Attack vectors:")
print(df['attack_vector'].value_counts())
print(f"\n   Score range: {df['base_score_v3'].min()} - {df['base_score_v3'].max()}")

# Save
out = PROCESSED_DIR / 'nvd_cves.csv'
df.to_csv(out, index=False)
print(f"\n💾 Saved to: {out}")
print(f"   Size: {out.stat().st_size / (1024*1024):.1f} MB")
print("\n✅ Done! Run retrain_vulnerability_model.py next.")