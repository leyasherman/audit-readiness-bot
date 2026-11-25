import os

DEBUG = os.getenv("DEBUG", "false").lower() == "true"

CORS_ALLOWED_ORIGINS = ["https://app.acme-health.example"]

DATABASE_URL = os.environ["DATABASE_URL"]
