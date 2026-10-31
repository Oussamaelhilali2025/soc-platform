from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session
import uuid

from app.core.database import get_db
from app.core.security import require_permission

router = APIRouter(
    prefix="/evenement-processus",
    tags=["evenement_processus"]
)


class EvenementProcessusCreate(BaseModel):
    id_evenement: uuid.UUID
    nom_processus: str | None = None
    chemin_processus: str | None = None
    pid: int | None = None
    ppid: int | None = None
    utilisateur: str | None = None
    niveau_integrite: str | None = None
    ligne_commande: str | None = None
    hash_processus: str | None = None
    nom_processus_parent: str | None = None

    @field_validator("pid", "ppid")
    @classmethod
    def validate_pid(cls, v):
        if v is not None and v < 0:
            raise ValueError("PID/PPID doit être >= 0")
        return v

    @field_validator("hash_processus")
    @classmethod
    def validate_hash(cls, v):
        if v is not None:
            if len(v) != 64:
                raise ValueError("hash_processus doit contenir 64 caractères")
            try:
                int(v, 16)
            except ValueError:
                raise ValueError("hash_processus doit être hexadécimal")
        return v


class EvenementProcessusUpdate(BaseModel):
    nom_processus: str | None = None
    chemin_processus: str | None = None
    pid: int | None = None
    ppid: int | None = None
    utilisateur: str | None = None
    niveau_integrite: str | None = None
    ligne_commande: str | None = None
    hash_processus: str | None = None
    nom_processus_parent: str | None = None

    @field_validator("pid", "ppid")
    @classmethod
    def validate_pid(cls, v):
        if v is not None and v < 0:
            raise ValueError("PID/PPID doit être >= 0")
        return v

    @field_validator("hash_processus")
    @classmethod
    def validate_hash(cls, v):
        if v is not None:
            if len(v) != 64:
                raise ValueError("hash_processus doit contenir 64 caractères")
            try:
                int(v, 16)
            except ValueError:
                raise ValueError("hash_processus doit être hexadécimal")
        return v


def serialize_row(row):
    result = dict(row._mapping)

    if isinstance(result.get("id_evenement"), (bytes, bytearray)):
        result["id_evenement"] = str(
            uuid.UUID(bytes=result["id_evenement"])
        )

    return result


@router.post("", status_code=201)
def create_evenement_processus(
    data: EvenementProcessusCreate,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("EVENT_READ"))
):
    # Vérifier que l'événement parent existe
    parent = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": data.id_evenement.bytes}
    ).first()

    if not parent:
        raise HTTPException(
            status_code=404,
            detail="evenement parent not found"
        )

    # Un seul sous-type processus par événement
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_processus
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": data.id_evenement.bytes}
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="evenement processus already exists"
        )

    db.execute(
        text("""
            INSERT INTO evenement_processus (
                id_evenement,
                nom_processus,
                chemin_processus,
                pid,
                ppid,
                utilisateur,
                niveau_integrite,
                ligne_commande,
                hash_processus,
                nom_processus_parent
            )
            VALUES (
                :id_evenement,
                :nom_processus,
                :chemin_processus,
                :pid,
                :ppid,
                :utilisateur,
                :niveau_integrite,
                :ligne_commande,
                :hash_processus,
                :nom_processus_parent
            )
        """),
        {
            "id_evenement": data.id_evenement.bytes,
            "nom_processus": data.nom_processus,
            "chemin_processus": data.chemin_processus,
            "pid": data.pid,
            "ppid": data.ppid,
            "utilisateur": data.utilisateur,
            "niveau_integrite": data.niveau_integrite,
            "ligne_commande": data.ligne_commande,
            "hash_processus": data.hash_processus,
            "nom_processus_parent": data.nom_processus_parent,
        }
    )

    db.commit()

    return {
        "id_evenement": str(data.id_evenement),
        "message": "Evenement processus created successfully"
    }


@router.get("/{id_evenement}")
def get_evenement_processus(
    id_evenement: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("EVENT_READ"))
):
    row = db.execute(
        text("""
            SELECT *
            FROM evenement_processus
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": id_evenement.bytes}
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="evenement processus not found"
        )

    return serialize_row(row)


@router.put("/{id_evenement}")
def update_evenement_processus(
    id_evenement: uuid.UUID,
    data: EvenementProcessusUpdate,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("EVENT_READ"))
):
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_processus
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": id_evenement.bytes}
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement processus not found"
        )

    updates = data.model_dump(exclude_unset=True)

    if not updates:
        return {
            "id_evenement": str(id_evenement),
            "message": "No changes"
        }

    allowed = {
        "nom_processus",
        "chemin_processus",
        "pid",
        "ppid",
        "utilisateur",
        "niveau_integrite",
        "ligne_commande",
        "hash_processus",
        "nom_processus_parent",
    }

    updates = {
        key: value
        for key, value in updates.items()
        if key in allowed
    }

    set_clause = ", ".join(
        f"`{key}` = :{key}"
        for key in updates
    )

    updates["id_evenement"] = id_evenement.bytes

    db.execute(
        text(f"""
            UPDATE evenement_processus
            SET {set_clause}
            WHERE id_evenement = :id_evenement
        """),
        updates
    )

    db.commit()

    return {
        "id_evenement": str(id_evenement),
        "message": "Evenement processus updated successfully"
    }


@router.delete("/{id_evenement}")
def delete_evenement_processus(
    id_evenement: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("EVENT_READ"))
):
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_processus
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": id_evenement.bytes}
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement processus not found"
        )

    db.execute(
        text("""
            DELETE FROM evenement_processus
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": id_evenement.bytes}
    )

    db.commit()

    return {
        "id_evenement": str(id_evenement),
        "message": "Evenement processus deleted successfully"
    }