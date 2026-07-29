from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel, EmailStr, Field, field_validator
import bcrypt
import uuid
import jwt
from db.config import db
import os
from dotenv import load_dotenv
import re

load_dotenv()
user_router = APIRouter()
SECRET_KEY = os.getenv("SECRET_KEY").encode("utf-8")
ALGORITHM = os.getenv("ALGORITHM")

class RegisterRequest(BaseModel):
    name:str = Field(min_length=2, max_length=100)
    email:EmailStr 
    password:str = Field(min_length=8, max_length=100)
    user_type:str

class LoginRequest(BaseModel):
    email:str
    password:str

@field_validator("password")
@classmethod
def validate_password_complexity(cls, value: str) -> str:
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must contain at least one number.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", value):
            raise ValueError("Password must contain at least one special character.")
        return value

@user_router.post("/register")
async def register_user(user:RegisterRequest):
    users_collection = db["users"]
    if users_collection.find_one({"email":user.email}):
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    user_id = str(uuid.uuid4())
    token = jwt.encode({"user_id" : user_id}, SECRET_KEY, algorithm=ALGORITHM)

### Database Insertion
    users_collection.insert_one({
        "user_id":user_id,
        "email":user.email,
        "password":hashed_pw.decode(),
        # "token":token,
        "name":user.name,
        "user_type":user.user_type
    })

    return{"token":token, "user_id":user_id, "user_type":user.user_type}

@user_router.post("/login")
async def login_user(user:LoginRequest):
    users_collection = db["users"]
    found_user = users_collection.find_one({"email":user.email})

    if not found_user or not bcrypt.checkpw(user.password.encode(), found_user["password"].encode()):
        raise HTTPException(status_code=400, detail="invalid username or password")
    
    token = jwt.encode({"user_id":found_user["user_id"]}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token":token, "user_id":found_user["user_id"], "user_type":found_user["user_type"]}