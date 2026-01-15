# Healthbuddy

Healthbuddy helps people keep health records, visit notes, and follow-ups together in one place, with a patient-controlled way to connect information from clinic visits.

## What’s here

- Patient health overview and searchable record timeline.
- Clinic workspace for patient invitations and consultation documents.
- Patient invitation claim, review, and clinic-access controls.
- Follow-up tracking and record-based information lookup.

## Run locally

Requires Python 3.11 or newer. In PowerShell, create an environment, install dependencies, and start the app:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:HEALTHBUDDY_SETUP_KEY = "choose-a-random-value-at-least-24-characters-long"
npm run migrate
npm start
```

Open [http://localhost:8000](http://localhost:8000). The local setup uses SQLite and stores uploaded files under `data/` on this device.

The clinic’s first account is created from the Clinic workspace using the setup key. Invitations are copied and shared by clinic staff; Healthbuddy does not send email. Use synthetic records while setting up the service. Do not enter real patient information.

For a PostgreSQL run with Docker Compose, copy `.env.example` to `.env`, replace both secret values, then run `docker compose up --build`.
