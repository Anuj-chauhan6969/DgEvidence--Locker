# 🔐 Digital Evidence Locker

A Flask-based **Digital Evidence Locker** designed for secure evidence storage, controlled access, integrity verification, and auditable evidence management.

> Portfolio project demonstrating Python/Flask, authentication, OTP-based verification, encrypted file storage, role-based access, database design, audit logging, and evidence integrity workflows.

## ✨ Key Features

- 🔐 User registration and login with OTP verification (2FA-style flow)
- 👥 Role-based access control with user/admin workflows
- 📁 Evidence upload for images, video, audio, documents, text, and other files
- 🔒 Server-side encryption for stored evidence
- #️⃣ SHA-256 integrity hashing
- 📂 Case management and evidence organization
- 🔎 Evidence search and filtering
- 🧾 Audit trail for important security and evidence actions
- 🗑️ Delete-request and approval workflow
- 📧 Email notifications and OTP delivery
- 📊 Admin dashboard and system settings
- 🛡️ Password hashing with bcrypt

## 🧰 Tech Stack

**Backend:** Python, Flask  
**Database:** SQLite  
**Security:** bcrypt, Cryptography, PBKDF2, SHA-256  
**Frontend:** HTML, CSS, JavaScript  
**Email:** SMTP  
**Version Control:** Git / GitHub

## 🏗️ Project Structure

```text
Digital-Evidence-Locker/
├── app.py
├── database.py
├── encryption_util.py
├── email_util.py
├── check_hash.py
├── image_en.py
├── video_en.py
├── audioen.py
├── textany_en.py
├── anyfile_en.py
├── test_route.py
├── test_search_fixed.py
├── requirements.txt
├── .env.example
├── static/
└── templates/
```

Runtime data such as databases, encrypted uploads, backups, temporary previews, virtual environments, and secrets are intentionally excluded from Git.

## 🚀 Local Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Digital-Evidence-Locker
```

### 2. Create a virtual environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy `.env.example` to `.env` and fill in your own values.

**Never commit `.env` to GitHub.**

For production, use a proper secrets manager or deployment platform environment variables.

### 5. Run

```bash
python app.py
```

Then open the local URL shown by Flask.

## 🔒 Security Notes

This repository intentionally does **not** contain:

- Real user evidence
- Local SQLite databases
- Backup databases
- SMTP passwords/app passwords
- Flask production secrets
- Server-side encryption secrets
- Virtual environments

Before deploying publicly, review authentication, CSRF protection, secure cookie settings, rate limiting, file validation, secret management, and production WSGI configuration.

## 🎯 Portfolio Highlights

This project demonstrates practical experience with:

- Secure application design
- Authentication and authorization
- Encryption and cryptographic key derivation
- File handling and storage
- Database CRUD and relational design
- Audit logging
- Email/OTP workflows
- Flask backend development
- Frontend/backend integration
- Git-based software delivery

## 📌 Disclaimer

This is an educational/portfolio project and should receive a professional security review before being used to store real-world sensitive evidence.
