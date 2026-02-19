# AptPulse (Backend)

AptPulse is a household chore management app designed to help roommates fairly distribute and track shared responsibilities.

This repository contains the **FastAPI + PostgreSQL backend** with:

- Email signup/login (with email verification)
- Group + members + invites
- Rotation plans (round-robin chores)
- Scheduled plans (premium/trial gated)
- In-app notifications
- WebSocket notifications
- Calendar view backed by `assignments` table
- **Alembic migrations** for safe schema upgrades in production

---

## Table of Contents

- [1) Project Structure](#1-project-structure)
- [2) Tech Stack](#2-tech-stack)
- [3) Requirements](#3-requirements)
- [4) Setup (Local Development)](#4-setup-local-development)
- [5) Environment Variables](#5-environment-variables)
- [6) Install Packages](#6-install-packages)
- [7) Run the API](#7-run-the-api)
- [8) Database Migrations (Alembic)](#8-database-migrations-alembic)
  - [8.1 Why migrations?](#81-why-migrations)
  - [8.2 One-time Alembic setup](#82-one-time-alembic-setup)
  - [8.3 Create a migration](#83-create-a-migration)
  - [8.4 Apply migrations (Upgrade)](#84-apply-migrations-upgrade)
  - [8.5 Rollback migrations (Downgrade)](#85-rollback-migrations-downgrade)
  - [8.6 Useful Alembic commands](#86-useful-alembic-commands)
  - [8.7 Production-safe migration workflow](#87-production-safe-migration-workflow)
- [9) Common Errors & Fixes](#9-common-errors--fixes)
- [10) Production Notes](#10-production-notes)

---

## 1) Project Structure

Typical backend layout:

```

Backend/
├── main.py
├── models.py
├── schemas.py
├── database.py
├── alembic.ini
└── alembic/
├── env.py
├── script.py.mako
└── versions/
├── 9b903196c188_baseline.py
└── c4ae1e6d2cd0_add_verified_at_to_identities.py

```

What each file does:

- **database.py**
  Loads DB URL from `.env` and creates the SQLAlchemy `engine`, `SessionLocal`, and `Base`.

- **models.py**
  All SQLAlchemy ORM models (tables).

- **schemas.py**
  Pydantic request/response models (API shapes).
  ⚠️ Important: keep Pydantic schemas **out of models.py** (to avoid Alembic import problems).

- **main.py**
  FastAPI app + endpoints.

- **alembic/**
  Alembic migrations folder:
  - `env.py` = migration runner config
  - `versions/*.py` = migration scripts (upgrade/downgrade)

---

## 2) Tech Stack

- Python 3.10+
- FastAPI
- SQLAlchemy (2.x)
- PostgreSQL
- Alembic (migrations)
- psycopg2-binary (Postgres driver)
- python-dotenv (loads `.env`)

---

## 3) Requirements

You need:

- Python 3.10+
- PostgreSQL installed and running locally or a cloud Postgres DB
- `pip` available

---

## 4) Setup (Local Development)

### Step 1: Create and activate a virtual environment

```bash
python -m venv myvenv
source myvenv/bin/activate
```

Confirm:

```bash
which python
# should show .../Backend/myvenv/bin/python
```

---

## 5) Environment Variables

Create a `.env` file in the `Backend/` folder:

```env
URL_DATABASE=postgresql://postgres:Purpose%402024@localhost:5432/AptPulse
```

### Important note about special characters in password:

- Your password has `@` which must be URL-encoded as `%40`
- If your password contains `%` you must encode it as `%25`

So always URL-encode credentials.

---

## 6) Install Packages

Inside the venv:

```bash
pip install fastapi uvicorn sqlalchemy alembic psycopg2-binary python-dotenv pydantic email-validator
```

Optional (recommended for dev):

```bash
pip install black ruff
```

---

## 7) Run the API

```bash
uvicorn main:app --reload
```

Open Swagger:

- [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 8) Database Migrations (Alembic)

### 8.1 Why migrations?

**Problem:** `Base.metadata.create_all()` creates tables only once.
It does **NOT** add new columns to existing tables.

Example:

- You add `verified_at` column in `models.Identity`
- Postgres table still doesn’t have it
- Login fails with: `column identities.verified_at does not exist`

✅ Solution: **Alembic migration** adds the column safely.

---

### 8.2 One-time Alembic setup

If Alembic is already initialized (you have `alembic/` and `alembic.ini`), skip this section.

To initialize:

```bash
python -m alembic init alembic
```

---

### 8.3 Create a migration

Whenever you change `models.py` (add column/table/index etc.):

```bash
python -m alembic revision --autogenerate -m "describe your change"
```

Example:

```bash
python -m alembic revision --autogenerate -m "add verified_at to identities"
```

This creates a file in `alembic/versions/`.

✅ Always open the generated migration file and quickly review it.

---

### 8.4 Apply migrations (Upgrade)

To apply all migrations up to the latest:

```bash
python -m alembic upgrade head
```

This is what you run in:

- local dev after schema change
- CI/CD pipeline
- production deploy process (after code deploy or before app start)

---

### 8.5 Rollback migrations (Downgrade)

If a deploy breaks or you need to revert:

Downgrade **one step**:

```bash
python -m alembic downgrade -1
```

Downgrade to a specific revision:

```bash
python -m alembic downgrade 9b903196c188
```

⚠️ Downgrades can be dangerous if they drop data.
In production, you normally avoid destructive downgrades.

---

### 8.6 Useful Alembic commands

Check current DB revision:

```bash
python -m alembic current
```

See migration history:

```bash
python -m alembic history --verbose
```

Mark DB as “already at head” without applying migrations (use carefully):

```bash
python -m alembic stamp head
```

---

### 8.7 Production-safe migration workflow

This is a safe “adult/prod” way to do schema upgrades:

1. **Create migration locally**

   ```bash
   python -m alembic revision --autogenerate -m "change"
   ```

2. **Review migration file**

   - Make sure it doesn’t drop tables unexpectedly
   - Make sure it matches what you intended

3. **Test upgrade**

   ```bash
   python -m alembic upgrade head
   ```

4. **Run your app + hit key endpoints**

   - signup
   - login
   - create group
   - create chore type

5. **Commit code + migration**

   - `models.py`
   - `alembic/versions/<revision>.py`

6. **In production deployment**

   - Run migrations before starting new app version:

     ```bash
     python -m alembic upgrade head
     ```

   - Then start the server

---

## 9) Common Errors & Fixes

### Error: `invalid interpolation syntax in postgresql://...%40...`

This happens because Alembic reads config using Python `configparser` and `%` can be treated specially.

✅ Fix options:

1. Make sure password is properly URL-encoded (`@` -> `%40`, `%` -> `%25`)
2. Prefer setting DB URL in `.env` and in `alembic/env.py` do:

   ```py
   config.set_main_option("sqlalchemy.url", os.getenv("URL_DATABASE").replace("%", "%%"))
   ```

   (This escapes `%` for configparser)

---

### Error: `ModuleNotFoundError: No module named psycopg2`

Install the driver in your venv:

```bash
pip install psycopg2-binary
```

---

### Error: `which alembic` points to `/opt/anaconda3/bin/alembic`

That means Alembic command is coming from Conda, not your venv.

✅ Always use:

```bash
python -m alembic ...
```

This guarantees the venv’s packages are used.

---

### Error: `NameError: BaseModel is not defined` while running Alembic

This usually happens when you accidentally put Pydantic schemas inside `models.py`.

✅ Fix:

- Keep **SQLAlchemy tables only** in `models.py`
- Move Pydantic schemas to `schemas.py`

---

### Error: `column identities.verified_at does not exist`

Means your DB schema is behind your models.

✅ Fix:

```bash
python -m alembic upgrade head
```

---

## 10) Production Notes

### Do NOT use `create_all()` in production

In `main.py`, remove:

```py
models.Base.metadata.create_all(bind=engine)
```

Because:

- it silently creates schema drift
- it won’t evolve schema safely
- migrations become unreliable

### Recommended production startup pattern

1. run migrations
2. start FastAPI

Example:

```bash
python -m alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## Quick Start Summary (Kid Version)

1. Make venv:

```bash
python -m venv myvenv
source myvenv/bin/activate
```

2. Install:

```bash
pip install fastapi uvicorn sqlalchemy alembic psycopg2-binary python-dotenv pydantic email-validator
```

3. Add `.env`:

```env
URL_DATABASE=postgresql://postgres:Purpose%402024@localhost:5432/AptPulse
```

4. Run migrations:

```bash
python -m alembic upgrade head
```

5. Start API:

```bash
uvicorn main:app --reload
```

That’s it ✅
