# Phishing URL Detector (Simple Web + Training)

This package includes:
- `url_rules.py` — heuristic engine
- `url_detector_web.py` — clean Flask web UI (uses heuristics + optional ML if model exists)
- `train_url_model.py` — trains an ML model from a KaggleHub dataset
- `models/` — output path for the trained model (`url_phish_model.joblib`)
- `requirements.txt`

## Quick start (Web UI)
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python url_detector_web.py
# open http://127.0.0.1:5000
```

## Train a model with KaggleHub
```python
# Download latest version (example dataset)
import kagglehub
path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
print("Path to dataset files:", path)
```

Then run:
```bash
python train_url_model.py --dataset "taruntiwarihp/phishing-site-urls" --out models/url_phish_model.joblib
# or local folder
python train_url_model.py --folder ./data --out models/url_phish_model.joblib
```

Restart the web app — it will auto-load `models/url_phish_model.joblib` and show **ML probability** next to the heuristic score.
