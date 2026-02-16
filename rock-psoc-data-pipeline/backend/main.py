"""
FastAPI Backend - Main Application
Serves the React dashboard with Supabase integration and ML predictions
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import uvicorn

from backend.routers import health, threats, predictions, stats
from backend.config import settings

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print("=" * 70)
    print("🚀 DASHBOARD BACKEND API STARTING")
    print("=" * 70)
    print(f"   Environment: {settings.ENVIRONMENT}")
    print(f"   Port: 8001")
    print(f"   Supabase: {'✅ Connected' if settings.SUPABASE_URL else '❌ Not configured'}")
    print("=" * 70)
    
    yield
    
    # Shutdown
    print("\n🛑 Dashboard Backend API shutting down...")

# Create FastAPI app
app = FastAPI(
    title="Cybersecurity Dashboard API",
    description="Backend API for threat intelligence dashboard with ML predictions",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Configure CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",      # React dev server
        "http://127.0.0.1:8080",
        "http://localhost:5173",      # Vite dev server
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["Health"])
app.include_router(threats.router, prefix="/api", tags=["Threats"])
app.include_router(predictions.router, prefix="/api", tags=["Predictions"])
app.include_router(stats.router, prefix="/api", tags=["Statistics"])

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Cybersecurity Dashboard API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health"
    }

if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )