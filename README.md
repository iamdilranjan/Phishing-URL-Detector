# 🛡️ Phishing URL Detector

Phishing websites trick users into sharing sensitive data like passwords or credit card details.  
This project detects **phishing URLs** using a combination of:

- ✅ **Heuristic rules** → checks for suspicious URL patterns (IP in domain, risky TLDs, subdomains, etc.)  
- ✅ **Machine Learning model** → TF-IDF n-grams + Logistic Regression  
- ✅ **Flask Web App** → user-friendly interface to test URLs interactively  

---

## ✨ Features
- 🔍 Rule-based analysis for quick checks  
- 🤖 Trainable ML model with TF-IDF + Logistic Regression  
- 🌐 Simple Flask web app for URL testing  
- 📊 Explainable predictions (which rules/words triggered)  

---

## 🚀 Quick Start

1. Clone the repo & install dependencies:
git clone https://github.com/iamdilranjan/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt

2. Train your model:

python train_url_model.py --folder ./data --out models/url_phish_model.joblib

3.Run the web app:

python url_detector_web.py


<img width="3420" height="2224" alt="image" src="https://github.com/user-attachments/assets/d2e0388f-c3b3-496e-89cb-a448843eb085" />


<img width="3420" height="2224" alt="image" src="https://github.com/user-attachments/assets/ddc077bc-5c31-4b95-818d-e089a5f17a6c" />

⚙️ Tech Stack

Python 3.10+

Flask

scikit-learn

pandas, numpy, scipy

tldextract, idna

📌 Future Work

🔹 Add deep learning (BERT for phishing detection)

🔹 Deploy online with Streamlit/Docker

🔹 Use real-time phishing feeds for training

📜 License

MIT © 2025 Dilranjan Kumar
