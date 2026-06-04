#!/bin/sh

# =====================================================================
# 🚀 CYBEROPS STARTUP ENTRYPOINT
# =====================================================================

echo "[CYBEROPS ENGINE] Running startup checks..."

# Check and apply database migrations
echo "[CYBEROPS ENGINE] Applying Django database migrations..."
python manage.py makemigrations --noinput
python manage.py migrate --noinput

# Auto-populate API keys for existing profiles if missing
echo "[CYBEROPS ENGINE] Verifying User Profile API key bindings..."
python manage.py shell -c "from analyzer.models import UserProfile; [p.save() for p in UserProfile.objects.all() if not p.api_key]"

# Start Django development server
echo "[CYBEROPS ENGINE] Starting server on port 8000..."
exec python manage.py runserver 0.0.0.0:8000
