from fastapi import FastAPI, HTTPException, APIRouter
from pydantic import BaseModel
import bcrypt
import uuid
from jose import jwt
from db.config import db
import os
from dotenv import load_dotenv

load_dotenv()
user_router = APIRouter()
SECRET_KEY = os.getenv("SECRET_KEY").encode("utf-8")
ALGORITHM = os.getenv("ALGORITHM")

class RegisterRequest(BaseModel):
    name:str
    email:str
    password:str
    user_type:str

class LoginRequest(BaseModel):
    email:str
    password:str

@user_router.post("/register")
async def register_user(user:RegisterRequest):
    users_collection = db["users"]
    if users_collection.find_one({"email":user.email}):
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_pw = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())
    user_id = str(uuid.uuid4())
    token = jwt.encode({"user_id" : user_id}, SECRET_KEY, algorithm=ALGORITHM)

    users_collection.insert_one({
        "user_id":user_id,
        "email":user.email,
        "password":hashed_pw.decode(),
        "token":token,
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