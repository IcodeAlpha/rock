from huggingface_hub import HfApi
import os

api = HfApi()
REPO_ID = "Alfeesi/cybersecurity-ml-models"

# All files to upload
files = [
    # Main predictor
    ("models/predictor.pkl", "predictor.pkl"),

    # Preprocessors
    ("models/preprocessors/intrusion_label_encoder.pkl", "preprocessors/intrusion_label_encoder.pkl"),
    ("models/preprocessors/intrusion_scaler.pkl", "preprocessors/intrusion_scaler.pkl"),
    ("models/preprocessors/phishing_scaler.pkl", "preprocessors/phishing_scaler.pkl"),
    ("models/preprocessors/severity_encoder.pkl", "preprocessors/severity_encoder.pkl"),
    ("models/preprocessors/vulnerability_scaler.pkl", "preprocessors/vulnerability_scaler.pkl"),
    ("models/preprocessors/intrusion_feature_names.json", "preprocessors/intrusion_feature_names.json"),
    ("models/preprocessors/phishing_feature_names.json", "preprocessors/phishing_feature_names.json"),
    ("models/preprocessors/vulnerability_feature_names.json", "preprocessors/vulnerability_feature_names.json"),

    # Saved models - Intrusion
    ("models/saved_models/intrusion_detection/best_model.pkl", "saved_models/intrusion_detection/best_model.pkl"),
    ("models/saved_models/intrusion_detection/rf_model.pkl", "saved_models/intrusion_detection/rf_model.pkl"),
    ("models/saved_models/intrusion_detection/xgb_model.pkl", "saved_models/intrusion_detection/xgb_model.pkl"),

    # Saved models - Phishing
    ("models/saved_models/phishing_detection/best_model.pkl", "saved_models/phishing_detection/best_model.pkl"),
    ("models/saved_models/phishing_detection/rf_model.pkl", "saved_models/phishing_detection/rf_model.pkl"),
    ("models/saved_models/phishing_detection/xgb_model.pkl", "saved_models/phishing_detection/xgb_model.pkl"),

    # Saved models - Vulnerability
    ("models/saved_models/vulnerability_scoring/rf_classifier.pkl", "saved_models/vulnerability_scoring/rf_classifier.pkl"),
    ("models/saved_models/vulnerability_scoring/rf_regressor.pkl", "saved_models/vulnerability_scoring/rf_regressor.pkl"),
    ("models/saved_models/vulnerability_scoring/xgb_classifier.pkl", "saved_models/vulnerability_scoring/xgb_classifier.pkl"),
    ("models/saved_models/vulnerability_scoring/xgb_regressor.pkl", "saved_models/vulnerability_scoring/xgb_regressor.pkl"),
]

print("🚀 Starting upload to Hugging Face...")
for local_path, repo_path in files:
    if os.path.exists(local_path):
        print(f"   Uploading {local_path}...")
        api.upload_file(
            path_or_fileobj=local_path,
            path_in_repo=repo_path,
            repo_id=REPO_ID,
            repo_type="model"
        )
        print(f"   ✅ Done: {repo_path}")
    else:
        print(f"   ⚠️ Skipped (not found): {local_path}")

print("\n🎉 Upload complete!")
print(f"View your models at: https://huggingface.co/{REPO_ID}")