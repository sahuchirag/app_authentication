from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import bcrypt
import jwt
import datetime
import threading
import time
import uvicorn

app = FastAPI()

# In-memory dummy database
dummy_db = {}  # {email: {"password": hashed_password, "tokens": {token: expiry_time}}}

# Secret Key & Token Expiry
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
TOKEN_EXPIRY_MINUTES = 5


# Request Models
class UserCreate(BaseModel):
    email: str
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class TokenData(BaseModel):
    token: str


# Password Hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed_password.encode())


# JWT Token Generation
def create_access_token(email: str):
    expire_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=TOKEN_EXPIRY_MINUTES)
    payload = {"sub": email, "exp": expire_time}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

    # Store token in user data
    if email in dummy_db:
        dummy_db[email]["tokens"][token] = expire_time
    return token


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Health Check
@app.get("/health", tags=["system"], summary="Health Check Endpoint")
def health_check():
    """
    Returns the current health status of the API and UTC timestamp.
    """
    return {"status": "healthy", "timestamp": datetime.datetime.utcnow()}

# **1. SIGN UP**
@app.post("/signup")
def signup(user: UserCreate):
    if user.email in dummy_db:
        raise HTTPException(status_code=400, detail="User already exists")

    dummy_db[user.email] = {"password": hash_password(user.password), "tokens": {}}
    return {"message": "User registered successfully"}


# **2. SIGN IN**
@app.post("/signin")
def signin(user: UserLogin):
    if user.email not in dummy_db or not verify_password(user.password, dummy_db[user.email]["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(user.email)
    return {"access_token": token}


# **3. AUTHORIZATION CHECK**
@app.get("/protected")
def protected_route(token: str):
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    email = payload["sub"]
    if token not in dummy_db.get(email, {}).get("tokens", {}):
        raise HTTPException(status_code=401, detail="Token revoked or expired")

    return {"message": "Access granted", "user": email}


# **4. TOKEN REVOCATION**
@app.post("/revoke-token")
def revoke_token(token_data: TokenData):
    for user in dummy_db.values():
        if token_data.token in user["tokens"]:
            del user["tokens"][token_data.token]
            return {"message": "Token revoked"}
    
    return {"message": "Token not found"}


# **5. REFRESH TOKEN**
@app.post("/refresh-token")
def refresh_token(token_data: TokenData):
    payload = decode_token(token_data.token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    email = payload["sub"]
    new_token = create_access_token(email)
    return {"new_access_token": new_token}


@app.get("/debug/db", tags=["debug"], summary="View Database Contents")
def debug_view_db(admin_key: str = None):
    """
    Debug endpoint to view the contents of the in-memory database.
    Requires admin_key for authorization.
    """
    if admin_key != "supersecretadmin":
        raise HTTPException(status_code=403, detail="Unauthorized access")
    return dummy_db


# **6. BACKGROUND CLEANUP PROCESS**
def cleanup_expired_tokens():
    while True:
        time.sleep(60)  # Run cleanup every 60 seconds
        now = datetime.datetime.utcnow()
        for user in dummy_db.values():
            expired_tokens = [t for t, exp in user["tokens"].items() if exp < now]
            for t in expired_tokens:
                del user["tokens"][t]


# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_expired_tokens, daemon=True)
cleanup_thread.start()


# Run the API using:
# uvicorn main:app --reload