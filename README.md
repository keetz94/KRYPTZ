# KRYPTZ — Secret Chat App

KRYPTZ is a **Flask + Socket.IO** based real-time chat app with a simple "rooms + password" flow.
Messages are stored in the database **encrypted with Fernet**, and users can be gated by **admin approval**.

> ⚠️ **Disclaimer:** This project aims for privacy, but it does **not** guarantee 100% anonymity or 100% security. For production use, you must add proper hardening (SSL/HTTPS, etc.).

---

## Features

- **Real-time chat:** Powered by Flask-SocketIO & Eventlet.
- **Room System:** Create rooms with passwords.
- **Admin Panel:** Approve users, toggle admin status, ban/unban users.
- **Security:** Messages are stored **encrypted** in the DB (using Fernet symmetric encryption).
- **Media:** Image upload support (`png/jpg/jpeg/gif/webp`).
- **Protection:** Math captcha for login/register and basic anti-spam (rate limiting).

---

## Tech Stack

- Python + Flask
- Flask-Login (Authentication)
- Flask-SQLAlchemy (SQLite Database)
- Flask-SocketIO (WebSockets)
- Cryptography (Fernet Encryption)

---

## Setup & Run

### 1) Install Dependencies
Open your terminal/command prompt in the project folder and run:

    pip install -r requirements.txt

### 2) Configuration (Optional but Recommended)
To create the initial **Admin** account automatically on the first run, you need to set an environment variable.

**Windows (CMD):**

    set ADMIN_PASSWORD=MySuperSecretPassword
    set FLASK_SECRET_KEY=random-string-here

**Linux / Mac / Git Bash:**

    export ADMIN_PASSWORD="MySuperSecretPassword"
    export FLASK_SECRET_KEY="random-string-here"

> *Note: If you don't set `ADMIN_PASSWORD`, no admin account will be created automatically. You would need to edit the database manually.*

### 3) Run the Application
Start the server:

    python app.py

*On the first run, `database.db` and `chat_secret.key` will be created automatically.*

### 4) Access
Open your browser and navigate to:
**http://localhost:5000**

- **Login:** Use username `admin` and the password you set in Step 2.
- **Register:** New users can register, but they cannot log in until an **Admin approves** them via the Admin Panel.

---

## Chat Commands (Admin Only)

Admins can execute these commands directly in the chat input box:

- `/clear`
  Deletes **all** messages in the current room.
- `/clear <number>`
  Deletes the last `<number>` messages (e.g., `/clear 50`).
- `/topic <new topic>`
  Changes the description/topic of the current room.
- `/deletechannel`
  Archives the room's messages to a text file (in `static/archives`) and **deletes the room permanently**.

---

## ⚠️ Important Security Notes

1.  **`chat_secret.key`**: This file holds the encryption key for all messages. **Do not lose it** and **never commit it to GitHub**. If you lose this file, all previous chat history becomes unreadable.
2.  **`database.db`**: Contains all user data and hashed passwords. Do not share or commit this file.
3.  **Deployment**: This setup uses `eventlet` for the WSGI server, which is good for production, but you should run it behind a reverse proxy like **Nginx** with SSL (HTTPS) enabled for real security.

---

## License

This project is for educational purposes. Use at your own risk.
