# Pink Members: website + backend + database

Node.js (Express) backend with a database. Sign-ups are saved permanently and shared across all devices.

- **Local:** uses SQLite (file `data/members.db`), no setup.
- **Render / production:** uses PostgreSQL via `DATABASE_URL`.

## Run locally

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy on Render (GitHub → Render)

1. Push this folder to a GitHub repository.
2. In Render: **New → Blueprint**, pick the repo. `render.yaml` creates the web service and a PostgreSQL database and links them (it also generates `JWT_SECRET`).
3. Wait for the deploy, then open the service URL.

Note: Render's free PostgreSQL databases expire after a limited period; use a paid database plan for a long-lived membership list.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/signup` | `{name, phone, password}` → creates member, returns token |
| POST | `/api/login` | `{phone, password}` → returns token |
| GET | `/api/members` | Members list (needs `Authorization: Bearer <token>`) |
| GET | `/api/health` | Health check |

## Database

Table `members`: `id`, `real_name`, `phone` (unique), `password_hash` (bcrypt), `created_at`.
Passwords are never stored or returned in plain text.

## Changes from the original page

- Login now asks for **phone number + password** (password alone can't identify a member once passwords are hashed, and two members could share one).
- Fixed the "SIGH UP" button typo → "SIGN UP".
- Demo notices removed; the page now uses the server instead of localStorage.
- The page script moved to `public/app.js` (required by the security headers).
- Only logged-in members can view the member list.
