# 🔐 Unified QR & URL Phishing Detection

A machine learning-powered cybersecurity application that detects phishing and malicious URLs from both direct user input and QR codes. The system combines machine learning with heuristic analysis and domain intelligence to provide accurate threat detection along with an easy-to-understand security report.

---

## 🚀 Features

- 🔗 Analyze URLs for phishing and malicious behavior
- 📱 Scan QR codes and analyze embedded URLs
- 🤖 Machine Learning based fraud detection
- 🌍 Domain Intelligence (WHOIS lookup)
- 📅 Domain age detection
- 🏢 Registrar information
- 🛡️ Security Score (0–100)
- ⚠️ Risk Level Classification (Safe, Low, Medium, High, Critical)
- 🔒 HTTPS security verification
- 🌐 IP Address resolution
- 🚩 Suspicious URL indicator detection
- ✅ Trusted domain whitelist
- 📊 Confidence score for every prediction
- 📜 Analysis history using SQLite database
- 💬 User feedback collection for future model improvement

---

# 🛠️ Tech Stack

| Category | Technologies |
|----------|--------------|
| Frontend | Streamlit |
| Backend | Python |
| Machine Learning | Scikit-learn (Random Forest) |
| Data Processing | Pandas, NumPy |
| QR Processing | OpenCV, pyzbar, Pillow |
| Database | SQLite |
| Domain Intelligence | python-whois |
| URL Parsing | urllib, socket |
| Environment | uv |

---

# 🧠 Machine Learning Model

The application uses a **Random Forest Classifier** trained on URL-based features including:

- URL Length
- Domain Length
- Path Length
- HTTPS Usage
- HTTP Usage
- IP Address Detection
- Suspicious Keywords
- Number of Digits
- Number of Slashes
- Query Parameters
- Entropy
- Suspicious Top-Level Domains
- Domain Age
- Young Domain Detection
- Additional heuristic security features

The extracted features are normalized using **StandardScaler** before prediction.

---

# 📊 Detection Output

For every analyzed URL the system provides:

- Fraudulent / Safe prediction
- Confidence score
- Risk Level
- Security Score
- Domain Information
- Registrar
- Domain Age
- HTTPS Status
- IP Address
- Suspicious Indicators
- Explanation of the prediction

---

# 📂 Project Structure

```
Unified-QR-and-URL-Phishing-Detection
│
├── streamlit_app.py
├── Notebook/
│   ├── fraud_detection_model_.py
│   └── trained_models/
├── helpers/
├── database/
├── images/
├── README.md
├── pyproject.toml
└── uv.lock
```

---

# ⚙️ Installation

Clone the repository

```bash
git clone https://github.com/Blessy-K/Unified-QR-and-URL-Phishing-Detection.git
```

Move into the project

```bash
cd Unified-QR-and-URL-Phishing-Detection
```

Install dependencies

```bash
uv sync
```

Run the application

```bash
uv run streamlit run streamlit_app.py
```

---



---

# 🎯 Future Enhancements

- Deep Learning based phishing detection
- Real-time blacklist integration
- Browser extension
- Email phishing detection
- Android application
- Continuous model retraining using user feedback

---

# 👩‍💻 Author

**Blessy K**

B.Tech – Computer Science & Engineering (Data Science)

---

# ⭐ If you like this project

Give this repository a ⭐ on GitHub.