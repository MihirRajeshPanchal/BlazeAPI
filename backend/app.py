import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.endpoints.management import router as management_router
from backend.endpoints.dynamic import router as dynamic_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

app = FastAPI(
    title="MachAPI — Dynamic AI Endpoint Builder",
    description="Register custom AI-powered endpoints at runtime (PostgreSQL backed).",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(management_router)
app.include_router(dynamic_router)


# ✅ CRITICAL FIX
@app.on_event("startup")
async def startup():
    from backend.services.registry_service import init_db_pool, init_db
    await init_db_pool()
    await init_db()


@app.get("/")
async def root():
    return {"status": "running", "docs": "/docs"}


@app.get("/health")
async def health():
    return {"status": "ok"}