# KRYPTZ — Secret Chat App

KRYPTZ is a **Flask + Socket.IO** based real-time chat app with a simple “rooms + password” flow.  
Messages are stored in the database **encrypted with Fernet**, and users can be gated by **admin approval**.

> ⚠️ Disclaimer: This project aims for privacy, but it does **not** guarantee 100% anonymity or 100% security. For production use, you must add proper hardening.

---

## Features

- Real-time chat (Flask-SocketIO)
- Room system + room passwords
- Admin panel: approve users, toggle admin, ban/unban
- Simple math captcha for login/register
- Messages stored **encrypted** in DB (Fernet)
- Image upload (`png/jpg/jpeg/gif/webp`)
- Basic anti-spam (rate limiting for fast messages)

---

## Tech Stack

- Python + Flask
- Flask-Login
- Flask-SQLAlchemy (SQLite)
- Flask-SocketIO + eventlet
- cryptography (Fernet)

---

## Setup

### 1) Install dependencies
```bash
pip install -r requirements.txt
