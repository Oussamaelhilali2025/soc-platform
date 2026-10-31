from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_active_user,
)
from app.models.utilisateur import Utilisateur
from pydantic import BaseModel
from datetime import datetime, timezone


class RefreshRequest(BaseModel):
    refresh_token: str


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post("/login")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    u = (
        db.query(Utilisateur)
        .filter(Utilisateur.nom_utilisateur == form.username)
        .first()
    )

    if not u or not verify_password(
        form.password,
        u.mot_de_passe_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if getattr(u.statut, "value", u.statut) != "ACTIVE":
        raise HTTPException(
            status_code=403,
            detail="Inactive user",
        )

    u.derniere_connexion = datetime.now(timezone.utc)
    db.commit()

    return {
        "access_token": create_access_token(
            {"sub": u.nom_utilisateur}
        ),
        "refresh_token": create_refresh_token(
            {"sub": u.nom_utilisateur}
        ),
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh(body: RefreshRequest):
    p = decode_token(body.refresh_token)

    if p.get("type") != "refresh":
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token",
        )

    return {
        "access_token": create_access_token(
            {"sub": p["sub"]}
        ),
        "token_type": "bearer",
    }


@router.get("/me")
def me(
    u=Depends(get_current_active_user),
):
    roles = []
    permissions = set()

    for role in u.roles:
        roles.append(role.nom)

        for permission in role.permissions:
            permissions.add(permission.code)

    return {
        "id_utilisateur": str(u.id_utilisateur),
        "nom_utilisateur": u.nom_utilisateur,
        "email": u.email,
        "nom": u.nom,
        "prenom": u.prenom,
        "statut": getattr(u.statut, "value", u.statut),
        "roles": roles,
        "permissions": sorted(permissions),
    }