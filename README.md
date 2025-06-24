# 🔐 File Integrity Monitor

A Python-based GUI application that helps monitor file integrity by computing and comparing SHA-256 hashes. Detects added, deleted, or tampered files in real-time to ensure data integrity and traceability.


---

## 🛠️ Features

- 📁 Scan any directory for file changes
- 🔐 Uses **SHA-256 hashing** for strong integrity checks
- 📊 Displays summary: New, Deleted, Modified files
- 🖥️ Clean **dark-themed PyQt5 GUI**
- 📦 Exports results to logs (and can be extended for CSV/JSON output)

---

## 🧪 How It Works

1. On first scan, it computes and stores SHA-256 hashes of all files.
2. On subsequent scans:
   - If a file's hash has changed ➜ it's **Modified**
   - If a file is missing ➜ it's **Deleted**
   - If a new file appears ➜ it's **New**

---

## 📷 Screenshot

![Interface Preview](https://i.postimg.cc/PJnLZcnN/Screenshot-2025-06-24-194920.png)

---

## 🚀 Technologies Used

- **Python 3**
- **PyQt5** – for GUI
- **Watchdog** – for file monitoring
- **hashlib, os, json, datetime** – for hashing and file ops

---

## 📦 Installation

```bash
git clone https://github.com/WallaceScott240/Shamar.git
cd Shamar
pip install -r requirements.txt
python app.py
