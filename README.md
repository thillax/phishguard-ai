# 🔐 PhishGuard AI
### AI-Powered Phishing URL Detection & Threat Analysis System

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-Backend-black)
![ML](https://img.shields.io/badge/ML-RandomForest-green)
![Accuracy](https://img.shields.io/badge/Accuracy-96.92%25-brightgreen)

---

## 🎯 Overview
PhishGuard AI is a real-time phishing URL detection tool that combines 
Machine Learning with threat intelligence to identify malicious URLs 
with **96.92% accuracy**.

---

## ✨ Features
- 🤖 **ML Detection** — Random Forest classifier (96.92% accuracy)
- 🎯 **Threat Indicators** — 7 real-time security checks
- 🔒 **SSL Validation** — Certificate expiry & validity check
- 🌐 **Domain Analysis** — WHOIS-based domain age lookup
- 🛡️ **VirusTotal Integration** — Threat intelligence API
- 📊 **Risk Scoring** — Weighted 0–10 risk score
- 🖥️ **Iron Man HUD UI** — Animated cybersecurity dashboard

---

## 🛠️ Tech Stack
| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, JavaScript (Iron Man HUD) |
| Backend | Python, Flask |
| ML Model | Scikit-learn, Random Forest |
| Dataset | Phishing Dataset (11,054 URLs) |
| Security APIs | VirusTotal, WHOIS, SSL |
| Features | 30 URL-based features extracted |

---

## 📁 Project Structure
phishguard-ai/
├── src/
│   ├── feature_extraction.py
│   ├── whois_check.py
│   └── virustotal_check.py
├── templates/
│   └── index.html
├── static/
├── app.py
└── requirements.txt
---

## 🚀 Run Locally
```bash
git clone https://github.com/thillax/phishguard-ai.git
cd phishguard-ai
pip install -r requirements.txt
python app.py
```
Open: http://127.0.0.1:5000

---

## 📊 Model Performance
| Metric | Score |
|---|---|
| Accuracy | 96.92% |
| Precision | 97% |
| Recall | 97% |
| F1-Score | 97% |
| Dataset Size | 11,054 URLs |

---

## 👩‍💻 Developer
**Thilaga N** — Cybersecurity Enthusiast | VAPT | AI Security  
📧 thilaga.cybersec@gmail.com  
🔗 [LinkedIn](https://www.linkedin.com/in/thilaga-nagaraj-cybersec)