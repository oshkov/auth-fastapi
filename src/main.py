from fastapi import FastAPI

from src.auth.router import router as auth_router
from src.auth.models import create_tables


app = FastAPI(title='Auth')


app.include_router(auth_router)


@app.on_event("startup")
async def startup_event():
    await create_tables()