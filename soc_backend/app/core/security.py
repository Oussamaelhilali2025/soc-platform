from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.models.utilisateur import Utilisateur

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool: return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password: str) -> str: return pwd_context.hash(password)

def _token(data: dict, minutes: int, token_type: str) -> str:
    payload = data.copy(); payload.update({"exp": datetime.now(timezone.utc)+timedelta(minutes=minutes), "type": token_type})
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_access_token(data: dict): return _token(data, settings.ACCESS_TOKEN_EXPIRE_MINUTES, "access")
def create_refresh_token(data: dict): return _token(data, settings.REFRESH_TOKEN_EXPIRE_MINUTES, "refresh")

def decode_token(token: str):
    try: return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError: raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate":"Bearer"})

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    payload = decode_token(token)
    if payload.get("type") != "access" or not payload.get("sub"): raise HTTPException(401, "Invalid access token")
    user = db.query(Utilisateur).filter(Utilisateur.nom_utilisateur == payload["sub"]).first()
    if not user: raise HTTPException(401, "User not found")
    return user

def get_current_active_user(current_user=Depends(get_current_user)):
    if getattr(current_user.statut, "value", current_user.statut) != "ACTIVE": raise HTTPException(status_code=403, detail="Inactive user")
    return current_user

def require_permission(code: str):
    def dep(current_user=Depends(get_current_active_user)):
        permissions = {p.code for r in current_user.roles for p in r.permissions}
        if code not in permissions: raise HTTPException(403, f"Missing permission: {code}")
        return current_user
    return dep
