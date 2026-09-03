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

## 📌 preview of project working

## 1. website start
<img width="1166" height="596" alt="image" src="https://github.com/user-attachments/assets/26a5fcca-8a7e-45cd-b837-d842c0f741fd" />
https://github.com/Anuj-chauhan6969/DgEvidence--Locker/blob/main/Digital-Evidence-Locker-Demo-Compressed.mp4

<img width="1164" height="594" alt="image" src="https://github.com/user-attachments/assets/2f3eb8df-5e8b-4c9f-8e91-d17c31ca0d31" />

<img width="546" height="636" alt="image" src="https://github.com/user-attachments/assets/f834bf94-6aa4-41dd-88f3-9b4906483f3c" />

<img width="1166" height="589" alt="image" src="https://github.com/user-attachments/assets/cdb4b31b-03e0-4fe1-94bf-39fd4e0c676f" />

<img width="1146" height="586" alt="image" src="https://github.com/user-attachments/assets/12508cb3-065f-45fa-863a-1f2f91f8aad4" />

<img width="1034" height="530" alt="image" src="https://github.com/user-attachments/assets/fbf77185-b74a-4ccd-bc50-f191699e8447" />

<img width="1174" height="590" alt="image" src="https://github.com/user-attachments/assets/0706f613-cdb4-4971-9cfd-11fb4ee8d166" />

<img width="1261" height="632" alt="image" src="https://github.com/user-attachments/assets/9418c55d-97bf-49bf-a378-f0286cdef00a" />

<img width="627" height="672" alt="image" src="https://github.com/user-attachments/assets/351bdd12-3c93-475d-9933-208a840bd3fb" />

<img width="386" height="518" alt="image" src="https://github.com/user-attachments/assets/38335a61-fee0-4595-965e-c87c80a64a3d" />

<img width="769" height="503" alt="image" src="https://github.com/user-attachments/assets/3ae41fbb-f291-4c35-a914-e20fffc034f5" />

<img width="1190" height="606" alt="image" src="https://github.com/user-attachments/assets/1b17b73f-d5d5-427e-8d4a-bc707ea9006f" />

<img width="1073" height="551" alt="image" src="https://github.com/user-attachments/assets/a123c5b4-37f5-41de-be61-411d1bf782a1" />


