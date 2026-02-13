# Phishing Detection System

This is a standalone system for detecting phishing emails, consisting of a Python backend and a Chrome Extension.

## 📂 Folder Structure
- **backend/**: Contains the Python Flask server for text analysis.
- **extension/**: Contains the Chrome Extension source code.

## 🚀 Setup Instructions

### 1. Backend (Python Server)
The backend processes email content sent from the extension.

**Prerequisites:**
- Python 3.8+ installed.

**Steps:**
1.  Open a terminal/command prompt.
2.  Navigate to the `backend` folder:
    ```bash
    cd backend
    ```
3.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4.  Run the server:
    ```bash
    python main.py
    ```
5.  You should see: `🚀 Starting Independent Phishing Detection Backend` on port 5000.

### 2. Chrome Extension
The extension extracts email content and sends it to the backend.

**Steps:**
1.  Open Google Chrome.
2.  Go to `chrome://extensions/`.
3.  Enable **Developer mode** (toggle in the top right corner).
4.  Click **Load unpacked**.
5.  Select the `extension` folder inside this directory.
6.  The **PhisHawk** extension icon should appear in your toolbar.

## 📧 How to Use
1.  Ensure the backend server is running.
2.  Open Gmail and select an email you want to analyze.
3.  Click the **PhisHawk** extension icon.
4.  Click **Analyze This Email**.
5.  View the risk score and analysis results in the popup window.

## ⚠️ Troubleshooting
- **Server Error / Connection Failed**: Make sure `python main.py` is running in the background.
- **Module not found**: Ensure you ran `pip install -r requirements.txt` successfully.
