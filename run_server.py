import sys
import uvicorn
from app.database import init_db

if __name__ == "__main__":
    print("🚀 Initializing Trusted Computing Database & Seeding Baseline Keys...")
    init_db()
    print("🔒 Starting IoT Attestation & Policy Server on http://127.0.0.1:8000")
    print("📖 API Documentation (Swagger): http://127.0.0.1:8000/docs")
    print("📊 Web Dashboard: http://127.0.0.1:8000/dashboard")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
