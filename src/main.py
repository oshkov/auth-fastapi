from fastapi import FastAPI

from src.auth.router import router as auth_router


app = FastAPI(title='Auth')


app.include_router(auth_router)
