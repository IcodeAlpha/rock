"""
Script 5: Train Phishing Detection Model (sklearn)
Uses PhishTank (phishing) + Majestic Million (legitimate) for real balanced dataset
"""

import pandas as pd
import numpy as np
import pickle
import json
import re
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
from datetime import datetime

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / 'data' / 'processed'
RAW_DIR = BASE_DIR / 'data' / 'raw'
MODEL_DIR = BASE_DIR / 'models' / 'saved_models' / 'phishing_detection'
PREP_DIR = BASE_DIR / 'models' / 'preprocessors'

MODEL_DIR.mkdir(parents=True, exist_ok=True)
PREP_DIR.mkdir(parents=True, exist_ok=True)

print("=" * 70)
print("🎣 TRAINING PHISHING DETECTION MODEL (REAL DATA)")
print("=" * 70)

def extract_url_features(url):
    """Extract numeric features from a URL string."""
    url = str(url)
    domain = re.sub(r'https?://', '', url).split('/')[0]
    return {
        'url_length':              len(url),
        'num_dots':                url.count('.'),
        'num_hyphens':             url.count('-'),
        'num_underscores':         url.count('_'),
        'num_slashes':             url.count('/'),
        'num_at_symbols':          url.count('@'),
        'num_question_marks':      url.count('?'),
        'has_https':               int(url.startswith('https')),
        'has_http':                int(url.startswith('http://')),
        'has_ip':                  int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        'has_suspicious_tld':      int(bool(re.search(r'\.(xyz|top|club|online|site|icu|tk|ml|ga|cf|gq)($|/)', url))),
        'has_url_shortener':       int(bool(re.search(r'(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly)', url))),
        'has_suspicious_keyword':  int(bool(re.search(r'(login|verify|secure|account|update|confirm|bank|paypal)', url, re.I))),
        'num_subdomains':          len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0,
        'domain_length':           len(domain),
        'has_double_slash':        int('//' in url[7:]),
        'digit_ratio':             sum(c.isdigit() for c in url) / max(len(url), 1),
        'special_char_ratio':      sum(c in '!@#$%^&*()' for c in url) / max(len(url), 1),
        'num_ampersands':          url.count('&'),
        'num_equals':              url.count('='),
    }

# Load PhishTank data (phishing URLs)
print("\n📥 Loading PhishTank phishing URLs...")
phish_df = pd.read_csv(DATA_DIR / 'phishtank_latest.csv')
phish_urls = phish_df['url'].dropna().head(50000)
print(f"   Phishing URLs: {len(phish_urls):,}")

# Load Majestic Million (legitimate domains)
print("\n📥 Loading Majestic Million legitimate domains...")
legit_df = pd.read_csv(RAW_DIR / 'majestic_million.csv')
# Convert domains to URLs
legit_urls = ('https://' + legit_df['Domain'].dropna()).head(50000)
print(f"   Legitimate URLs: {len(legit_urls):,}")

# Extract features
print("\n🔧 Extracting URL features...")
print("   Processing phishing URLs...")
phish_features = pd.DataFrame([extract_url_features(u) for u in phish_urls])
phish_features['label'] = 1

print("   Processing legitimate URLs...")
legit_features = pd.DataFrame([extract_url_features(u) for u in legit_urls])
legit_features['label'] = 0

# Combine
combined = pd.concat([phish_features, legit_features], ignore_index=True)
combined = combined.fillna(0)
print(f"\n   Total samples: {len(combined):,}")
print(f"   Phishing:   {(combined['label']==1).sum():,}")
print(f"   Legitimate: {(combined['label']==0).sum():,}")

# Features and labels
feature_cols = [c for c in combined.columns if c != 'label']
X = combined[feature_cols]
y = combined['label']

print(f"\n   Features: {list(feature_cols)}")

# Scale
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"\n✂️  Train: {len(X_train):,}  Test: {len(X_test):,}")

# Train
print("\n🚀 Training Random Forest...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=10,
    min_samples_leaf=5,
    max_features='sqrt',
    random_state=42,
    n_jobs=-1,
    class_weight='balanced',
    verbose=1
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\n✅ Accuracy: {accuracy*100:.2f}%")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Feature importance
print("\n🎯 Top 10 Most Important Features:")
importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': model.feature_importances_
}).sort_values('importance', ascending=False)
for _, row in importance.head(10).iterrows():
    print(f"   {row['feature']:30s}: {row['importance']:.4f}")

# Save
print("\n💾 Saving model...")
with open(MODEL_DIR / 'best_model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open(MODEL_DIR / 'rf_model.pkl', 'wb') as f:
    pickle.dump(model, f)
with open(PREP_DIR / 'phishing_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
with open(PREP_DIR / 'phishing_feature_names.json', 'w') as f:
    json.dump(list(feature_cols), f)

print(f"   Model saved to: {MODEL_DIR}")
print(f"\n✅ Phishing detection model ready!")
print(f"   Accuracy: {accuracy*100:.2f}% on real URLs")