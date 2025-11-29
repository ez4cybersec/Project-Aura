Setup Guide (Quick)
1. Backend Setup (Django)
cd aura/backend
python -m venv venv
venv\Scripts\activate   # Windows

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver

Backend runs at: http://localhost:8000


2. Frontend Setup (React/Vite)
cd aura
npm install
npm run dev


Run Both Services
Backend: python manage.py runserver
Frontend: npm run dev

Troubleshooting
Missing Django package?
pip install -r requirements.txt
Frontend errors?
npm install or delete node_modules and reinstall.