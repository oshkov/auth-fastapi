from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserRead(BaseModel):
    email: str
    username: str


class UserLogin(BaseModel):
    email: str
    password: str