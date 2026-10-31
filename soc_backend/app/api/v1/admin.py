from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import (
    require_permission,
    get_password_hash,
)
from app.models.utilisateur import Utilisateur
from app.models.role import Role
from app.models.permission import Permission


router = APIRouter(
    prefix="/admin",
    tags=["Administration"],
)


# ============================================================
# SCHEMA CREATION UTILISATEUR
# ============================================================

class AdminUserCreate(BaseModel):
    nom_utilisateur: str
    email: str
    nom: str
    prenom: str
    mot_de_passe: str
    id_role: UUID
    statut: str = "ACTIVE"


# ============================================================
# UTILISATEURS
# ============================================================

@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("USER_READ")
    ),
):
    users = (
        db.query(Utilisateur)
        .order_by(
            Utilisateur.date_creation.desc()
        )
        .all()
    )

    return [
        {
            "id_utilisateur": str(
                user.id_utilisateur
            ),
            "nom_utilisateur": user.nom_utilisateur,
            "email": user.email,
            "nom": user.nom,
            "prenom": user.prenom,
            "statut": user.statut,
            "derniere_connexion": (
                user.derniere_connexion.isoformat()
                if user.derniere_connexion
                else None
            ),
            "date_creation": (
                user.date_creation.isoformat()
                if user.date_creation
                else None
            ),
            "roles": [
                {
                    "id_role": str(role.id_role),
                    "nom": role.nom,
                    "description": role.description,
                }
                for role in user.roles
            ],
        }
        for user in users
    ]


# ============================================================
# CREER UN UTILISATEUR
# ============================================================

@router.post("/users")
def create_user(
    payload: AdminUserCreate,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("USER_CREATE")
    ),
):
    # --------------------------------------------------------
    # Validation statut
    # --------------------------------------------------------

    if payload.statut not in {
        "ACTIVE",
        "INACTIVE",
        "LOCKED",
    }:
        raise HTTPException(
            status_code=400,
            detail="Statut invalide.",
        )

    # --------------------------------------------------------
    # Nettoyage des valeurs
    # --------------------------------------------------------

    nom_utilisateur = (
        payload.nom_utilisateur.strip()
    )

    email = payload.email.strip()

    nom = payload.nom.strip()

    prenom = payload.prenom.strip()

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not nom_utilisateur:
        raise HTTPException(
            status_code=400,
            detail="Le nom d'utilisateur est obligatoire.",
        )

    if not email:
        raise HTTPException(
            status_code=400,
            detail="L'email est obligatoire.",
        )

    if not nom:
        raise HTTPException(
            status_code=400,
            detail="Le nom est obligatoire.",
        )

    if not prenom:
        raise HTTPException(
            status_code=400,
            detail="Le prénom est obligatoire.",
        )

    if not payload.mot_de_passe:
        raise HTTPException(
            status_code=400,
            detail="Le mot de passe est obligatoire.",
        )

    if len(payload.mot_de_passe) < 8:
        raise HTTPException(
            status_code=400,
            detail=(
                "Le mot de passe doit contenir "
                "au moins 8 caractères."
            ),
        )

    # --------------------------------------------------------
    # Vérifier rôle
    # --------------------------------------------------------

    role = (
        db.query(Role)
        .filter(
            Role.id_role == payload.id_role
        )
        .first()
    )

    if not role:
        raise HTTPException(
            status_code=404,
            detail="Rôle introuvable.",
        )

    # --------------------------------------------------------
    # Vérifier username
    # --------------------------------------------------------

    existing_username = (
        db.query(Utilisateur)
        .filter(
            Utilisateur.nom_utilisateur
            == nom_utilisateur
        )
        .first()
    )

    if existing_username:
        raise HTTPException(
            status_code=409,
            detail=(
                "Ce nom d'utilisateur "
                "existe déjà."
            ),
        )

    # --------------------------------------------------------
    # Vérifier email
    # --------------------------------------------------------

    existing_email = (
        db.query(Utilisateur)
        .filter(
            Utilisateur.email == email
        )
        .first()
    )

    if existing_email:
        raise HTTPException(
            status_code=409,
            detail=(
                "Cette adresse email "
                "existe déjà."
            ),
        )

    # --------------------------------------------------------
    # Hash du mot de passe
    # --------------------------------------------------------

    password_hash = get_password_hash(
        payload.mot_de_passe
    )

    # --------------------------------------------------------
    # Création utilisateur
    # --------------------------------------------------------

    user = Utilisateur(
        nom_utilisateur=nom_utilisateur,
        email=email,
        nom=nom,
        prenom=prenom,
        mot_de_passe_hash=password_hash,
        statut=payload.statut,
    )

    # --------------------------------------------------------
    # Attribution du rôle
    # --------------------------------------------------------

    user.roles = [role]

    # --------------------------------------------------------
    # Enregistrement
    # --------------------------------------------------------

    try:
        db.add(user)

        db.commit()

        db.refresh(user)

    except IntegrityError as e:
        db.rollback()

        print(
            "========== CREATE USER INTEGRITY ERROR =========="
        )
        print(e)
        print(
            "=================================================="
        )

        raise HTTPException(
            status_code=409,
            detail=str(e.orig),
        )

    # --------------------------------------------------------
    # Réponse
    # --------------------------------------------------------

    return {
        "message": "Utilisateur créé avec succès.",
        "id_utilisateur": str(
            user.id_utilisateur
        ),
        "nom_utilisateur": user.nom_utilisateur,
        "email": user.email,
        "nom": user.nom,
        "prenom": user.prenom,
        "statut": user.statut,
        "role": {
            "id_role": str(role.id_role),
            "nom": role.nom,
        },
    }


# ============================================================
# ROLES
# ============================================================

@router.get("/roles")
def list_roles(
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("ROLE_MANAGE")
    ),
):
    roles = (
        db.query(Role)
        .order_by(Role.nom.asc())
        .all()
    )

    return [
        {
            "id_role": str(role.id_role),
            "nom": role.nom,
            "description": role.description,
            "permissions": [
                {
                    "id_permission": str(
                        permission.id_permission
                    ),
                    "code": permission.code,
                    "description": permission.description,
                }
                for permission in role.permissions
            ],
        }
        for role in roles
    ]


# ============================================================
# PERMISSIONS
# ============================================================

@router.get("/permissions")
def list_permissions(
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("ROLE_MANAGE")
    ),
):
    permissions = (
        db.query(Permission)
        .order_by(Permission.code.asc())
        .all()
    )

    return [
        {
            "id_permission": str(
                permission.id_permission
            ),
            "code": permission.code,
            "description": permission.description,
        }
        for permission in permissions
    ]


# ============================================================
# MODIFIER LE STATUT
# ============================================================

@router.patch("/users/{user_id}/status")
def update_user_status(
    user_id: UUID,
    statut: str,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("USER_UPDATE")
    ),
):
    if statut not in {
        "ACTIVE",
        "INACTIVE",
        "LOCKED",
    }:
        raise HTTPException(
            status_code=400,
            detail="Statut invalide",
        )

    user = (
        db.query(Utilisateur)
        .filter(
            Utilisateur.id_utilisateur
            == user_id
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur introuvable",
        )

    user.statut = statut

    db.commit()

    db.refresh(user)

    return {
        "message": (
            "Statut utilisateur mis à jour"
        ),
        "id_utilisateur": str(
            user.id_utilisateur
        ),
        "statut": user.statut,
    }


# ============================================================
# ATTRIBUER UN ROLE
# ============================================================

@router.patch(
    "/users/{user_id}/role/{role_id}"
)
def assign_role(
    user_id: UUID,
    role_id: UUID,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("ROLE_MANAGE")
    ),
):
    user = (
        db.query(Utilisateur)
        .filter(
            Utilisateur.id_utilisateur
            == user_id
        )
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur introuvable",
        )

    role = (
        db.query(Role)
        .filter(
            Role.id_role == role_id
        )
        .first()
    )

    if not role:
        raise HTTPException(
            status_code=404,
            detail="Rôle introuvable",
        )

    user.roles = [role]

    db.commit()

    db.refresh(user)

    return {
        "message": "Rôle utilisateur mis à jour",
        "id_utilisateur": str(
            user.id_utilisateur
        ),
        "roles": [
            {
                "id_role": str(r.id_role),
                "nom": r.nom,
            }
            for r in user.roles
        ],
    }