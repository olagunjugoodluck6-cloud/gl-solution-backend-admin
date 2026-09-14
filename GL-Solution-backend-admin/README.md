# GL Solution

A graphics design website with:
- Public homepage
- Portfolio/posts loaded from SQLite
- Administrator login
- Admin publishing and deletion
- Password hashing with bcrypt
- Secure session cookies
- Helmet security headers
- Login rate limiting
- Parameterized SQL queries
- Restricted image uploads

## Requirements
Install Node.js (LTS) on your computer.

## Setup
1. Open this folder in Visual Studio Code.
2. Open the VS Code terminal.
3. Run:
   npm install
4. Copy `.env.example` to `.env`.
5. Set a strong `SESSION_SECRET` and a strong `ADMIN_PASSWORD`.
6. Run:
   npm start
7. Open:
   http://localhost:3000
8. Admin:
   http://localhost:3000/admin/login

Default username is `admin`. The password is whatever you put in `.env`.

## Production security
Before putting the site online:
- Use HTTPS.
- Set NODE_ENV=production.
- Use a long random SESSION_SECRET.
- Use a unique strong admin password.
- Keep Node/dependencies updated.
- Back up the database and uploads.
- Consider 2FA and a managed database/storage service for a larger production site.
- Do not commit `.env` to GitHub.
