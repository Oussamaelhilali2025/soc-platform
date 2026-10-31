import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, select, insert, update, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evenement-mitre",
    tags=["evenement-mitre"]
)

md = MetaData()
_table = None
_evenement_table = None
_technique_table = None


def get_table(db: Session):
    global _table

    if _table is None:
        _table = Table(
            "evenement_mitre",
            md,
            autoload_with=db.bind
        )

    return _table


def get_evenement_table(db: Session):
    global _evenement_table

    if _evenement_table is None:
        _evenement_table = Table(
            "evenement",
            md,
            autoload_with=db.bind
        )

    return _evenement_table


def get_technique_table(db: Session):
    global _technique_table

    if _technique_table is None:
        _technique_table = Table(
            "technique_mitre",
            md,
            autoload_with=db.bind
        )

    return _technique_table


def uuid_to_bytes(value: str) -> bytes:
    try:
        return uuid.UUID(value).bytes
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=f"UUID invalide: {value}"
        )


def normalize_uuid(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes=bytes(value)))

    return value


def row_to_dict(row):
    data = dict(row._mapping)

    if "id_evenement" in data:
        data["id_evenement"] = normalize_uuid(data["id_evenement"])

    return data


class EvenementMitreCreate(BaseModel):
    id_evenement: str
    id_technique: str
    source_detection: str | None = None
    confiance: int | None = Field(default=None, ge=0, le=100)


class EvenementMitreUpdate(BaseModel):
    source_detection: str | None = None
    confiance: int | None = Field(default=None, ge=0, le=100)


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def create_relation(
    payload: EvenementMitreCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    evenement_table = get_evenement_table(db)
    technique_table = get_technique_table(db)

    # Conversion UUID texte -> BINARY(16)
    evenement_id = uuid_to_bytes(payload.id_evenement)

    # Vérifier que l'événement existe
    evenement_exists = db.execute(
        select(1)
        .select_from(evenement_table)
        .where(
            evenement_table.c.id_evenement == evenement_id
        )
    ).first()

    if not evenement_exists:
        raise HTTPException(
            status_code=404,
            detail="Événement introuvable"
        )

    # Vérifier que la technique existe
    technique_exists = db.execute(
        select(1)
        .select_from(technique_table)
        .where(
            technique_table.c.id_technique == payload.id_technique
        )
    ).first()

    if not technique_exists:
        raise HTTPException(
            status_code=404,
            detail="Technique MITRE introuvable"
        )

    # Vérifier si la relation existe déjà
    existing = db.execute(
        select(t).where(
            t.c.id_evenement == evenement_id,
            t.c.id_technique == payload.id_technique
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Cette relation événement/technique existe déjà"
        )

    # Création
    db.execute(
        insert(t).values(
            id_evenement=evenement_id,
            id_technique=payload.id_technique,
            source_detection=payload.source_detection,
            confiance=payload.confiance
        )
    )

    db.commit()

    return {
        "id_evenement": payload.id_evenement,
        "id_technique": payload.id_technique,
        "source_detection": payload.source_detection,
        "confiance": payload.confiance
    }


@router.get(
    "/{id_evenement}/{id_technique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def get_relation(
    id_evenement: str,
    id_technique: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    evenement_id = uuid_to_bytes(id_evenement)

    row = db.execute(
        select(t).where(
            t.c.id_evenement == evenement_id,
            t.c.id_technique == id_technique
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Relation événement/technique introuvable"
        )

    return row_to_dict(row)


@router.put(
    "/{id_evenement}/{id_technique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def update_relation(
    id_evenement: str,
    id_technique: str,
    payload: EvenementMitreUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    evenement_id = uuid_to_bytes(id_evenement)

    existing = db.execute(
        select(t).where(
            t.c.id_evenement == evenement_id,
            t.c.id_technique == id_technique
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Relation événement/technique introuvable"
        )

    values = {}

    if payload.source_detection is not None:
        values["source_detection"] = payload.source_detection

    if payload.confiance is not None:
        values["confiance"] = payload.confiance

    if values:
        db.execute(
            update(t)
            .where(
                t.c.id_evenement == evenement_id,
                t.c.id_technique == id_technique
            )
            .values(**values)
        )

        db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_evenement == evenement_id,
            t.c.id_technique == id_technique
        )
    ).first()

    return row_to_dict(row)


@router.delete(
    "/{id_evenement}/{id_technique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def delete_relation(
    id_evenement: str,
    id_technique: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    evenement_id = uuid_to_bytes(id_evenement)

    result = db.execute(
        delete(t).where(
            t.c.id_evenement == evenement_id,
            t.c.id_technique == id_technique
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Relation événement/technique introuvable"
        )

    db.commit()

    return {
        "message": "Relation événement/technique supprimée"
    }