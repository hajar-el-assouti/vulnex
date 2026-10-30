# VULNEX — Installation Guide

This guide explains how to set up VULNEX for local development.

## 1. Prerequisites

Install the following tools:

- Git
- Docker and Docker Compose
- Node.js and npm

## 2. Clone the repository

    git clone https://github.com/hajar-el-assouti/vulnex.git
    cd vulnex


## 3. Configure the backend

    cd backend
    cp .env.example .env

Open `.env` and configure the required environment variables.

Important:
- Generate a strong, unique POSTGRES_PASSWORD.
- Generate a random SECRET_KEY.
- Never commit `.env` to Git.
- Keep active testing disabled unless you have explicit authorization.

## 4. Start the backend

From the `backend/` directory:

    docker compose up -d --build

This starts PostgreSQL, Redis, FastAPI, Celery Worker,
and Celery Beat.

The backend is configured to listen locally on:

    http://localhost:8000

## 5. Configure the frontend

Open another terminal:

    cd frontend
    cp .env.example .env.local

Review the frontend environment variables and configure
the backend connection for your local setup.

## 6. Start the frontend

From the `frontend/` directory:

    npm ci
    npm run build
    npm run start

Open the URL shown by Next.js in your browser.

## 7. Stop the application

From the `backend/` directory:

    docker compose down

Do not use `docker compose down -v` unless you
intentionally want to delete persistent Docker volumes.

## Security Notice

VULNEX is intended exclusively for authorized
security assessments and educational use.

Never scan systems without permission.
