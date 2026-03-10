import importlib.util
spec = importlib.util.spec_from_file_location("prediction_api", "scripts/6_create_prediction_api.py")
mod = importlib.util.module_from_spec(spec)

# Stop it from running the main code at the bottom
mod.__name__ = "__not_main__"

try:
    spec.loader.exec_module(mod)
except Exception:
    pass

import joblib
p = joblib.load('models/predictor.pkl')

# Show all methods
methods = [m for m in dir(p) if not m.startswith('_')]
print("Methods:", methods)