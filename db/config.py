from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
db = client["loginpage_security_db"]