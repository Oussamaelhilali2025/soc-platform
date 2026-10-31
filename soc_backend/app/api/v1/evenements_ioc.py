import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evenement-ioc",
    tags=["evenement_ioc"]
)


class EvenementIOCCreate(BaseModel):
    id_evenement: uuid.UUID
    id_ioc: uuid.UUID
    role_ioc: str
    contexte: str | None = None


class EvenementIOCUpdate(BaseModel):
    role_ioc: str | None = None
    contexte: str | None = None


def serialize_row(row):
    result = dict(row._mapping)

    if isinstance(result.get("id_evenement"), (bytes, bytearray)):
        result["id_evenement"] = str(
            uuid.UUID(bytes=result["id_evenement"])
        )

    if isinstance(result.get("id_ioc"), (bytes, bytearray)):
        result["id_ioc"] = str(
            uuid.UUID(bytes=result["id_ioc"])
        )

    return result


@router.post("", status_code=201)
def create_evenement_ioc(
    data: EvenementIOCCreate,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("IOC_CREATE"))
):
    # Vérifier l'événement
    event = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement
            WHERE id_evenement = :id_evenement
        """),
        {"id_evenement": data.id_evenement.bytes}
    ).first()

    if not event:
        raise HTTPException(
            status_code=404,
            detail="evenement not found"
        )

    # Vérifier l'IOC
    ioc = db.execute(
        text("""
            SELECT id_ioc
            FROM ioc
            WHERE id_ioc = :id_ioc
        """),
        {"id_ioc": data.id_ioc.bytes}
    ).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="ioc not found"
        )

    # Vérifier la relation
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_ioc
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        {
            "id_evenement": data.id_evenement.bytes,
            "id_ioc": data.id_ioc.bytes
        }
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="evenement-ioc relation already exists"
        )

    if not data.role_ioc.strip():
        raise HTTPException(
            status_code=422,
            detail="role_ioc cannot be empty"
        )

    db.execute(
        text("""
            INSERT INTO evenement_ioc (
                id_evenement,
                id_ioc,
                role_ioc,
                contexte
            )
            VALUES (
                :id_evenement,
                :id_ioc,
                :role_ioc,
                :contexte
            )
        """),
        {
            "id_evenement": data.id_evenement.bytes,
            "id_ioc": data.id_ioc.bytes,
            "role_ioc": data.role_ioc,
            "contexte": data.contexte
        }
    )

    db.commit()

    return {
        "id_evenement": str(data.id_evenement),
        "id_ioc": str(data.id_ioc),
        "message": "Evenement IOC created successfully"
    }


@router.get("/{id_evenement}/{id_ioc}")
def get_evenement_ioc(
    id_evenement: uuid.UUID,
    id_ioc: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("IOC_READ"))
):
    row = db.execute(
        text("""
            SELECT *
            FROM evenement_ioc
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        {
            "id_evenement": id_evenement.bytes,
            "id_ioc": id_ioc.bytes
        }
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="evenement-ioc relation not found"
        )

    return serialize_row(row)


@router.put("/{id_evenement}/{id_ioc}")
def update_evenement_ioc(
    id_evenement: uuid.UUID,
    id_ioc: uuid.UUID,
    data: EvenementIOCUpdate,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("IOC_CREATE"))
):
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_ioc
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        {
            "id_evenement": id_evenement.bytes,
            "id_ioc": id_ioc.bytes
        }
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement-ioc relation not found"
        )

    updates = data.model_dump(exclude_unset=True)

    if "role_ioc" in updates:
        if updates["role_ioc"] is not None and not updates["role_ioc"].strip():
            raise HTTPException(
                status_code=422,
                detail="role_ioc cannot be empty"
            )

    allowed = {"role_ioc", "contexte"}

    updates = {
        key: value
        for key, value in updates.items()
        if key in allowed
    }

    if not updates:
        return {
            "id_evenement": str(id_evenement),
            "id_ioc": str(id_ioc),
            "message": "No changes"
        }

    set_clause = ", ".join(
        f"`{key}` = :{key}"
        for key in updates
    )

    updates["id_evenement"] = id_evenement.bytes
    updates["id_ioc"] = id_ioc.bytes

    db.execute(
        text(f"""
            UPDATE evenement_ioc
            SET {set_clause}
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        updates
    )

    db.commit()

    return {
        "id_evenement": str(id_evenement),
        "id_ioc": str(id_ioc),
        "message": "Evenement IOC updated successfully"
    }


@router.delete("/{id_evenement}/{id_ioc}")
def delete_evenement_ioc(
    id_evenement: uuid.UUID,
    id_ioc: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("IOC_CREATE"))
):
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_ioc
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        {
            "id_evenement": id_evenement.bytes,
            "id_ioc": id_ioc.bytes
        }
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement-ioc relation not found"
        )

    db.execute(
        text("""
            DELETE FROM evenement_ioc
            WHERE id_evenement = :id_evenement
              AND id_ioc = :id_ioc
        """),
        {
            "id_evenement": id_evenement.bytes,
            "id_ioc": id_ioc.bytes
        }
    )

    db.commit()

    return {
        "id_evenement": str(id_evenement),
        "id_ioc": str(id_ioc),
        "message": "Evenement IOC deleted successfully"
    }