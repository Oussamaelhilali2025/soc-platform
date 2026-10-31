import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, select, insert, update, delete, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/regles-detection",
    tags=["regles-detection"]
)

md = MetaData()
_table = None


def get_table(db: Session):
    global _table

    if _table is None:
        _table = Table(
            "regle_detection",
            md,
            autoload_with=db.bind
        )

    return _table


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

    if "id_regle_detection" in data:
        data["id_regle_detection"] = normalize_uuid(
            data["id_regle_detection"]
        )

    if data.get("date_creation") is not None:
        data["date_creation"] = data["date_creation"].isoformat()

    return data


class RegleDetectionCreate(BaseModel):
    source: str
    identifiant_externe: str = Field(min_length=1, max_length=100)
    nom: str = Field(min_length=1, max_length=255)
    description: str | None = None
    niveau: int | None = Field(default=None, ge=0, le=15)
    categorie: str | None = Field(default=None, max_length=100)
    statut: str = "ACTIVE"


class RegleDetectionUpdate(BaseModel):
    source: str | None = None
    identifiant_externe: str | None = Field(
        default=None,
        min_length=1,
        max_length=100
    )
    nom: str | None = Field(
        default=None,
        min_length=1,
        max_length=255
    )
    description: str | None = None
    niveau: int | None = Field(default=None, ge=0, le=15)
    categorie: str | None = Field(default=None, max_length=100)
    statut: str | None = None


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(require_permission("ALERT_CREATE"))]
)
def create_regle(
    payload: RegleDetectionCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    existing = db.execute(
        select(t).where(
            t.c.source == payload.source,
            t.c.identifiant_externe == payload.identifiant_externe
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Cette règle de détection existe déjà"
        )

    id_regle = uuid.uuid4().bytes

    db.execute(
        insert(t).values(
            id_regle_detection=id_regle,
            source=payload.source,
            identifiant_externe=payload.identifiant_externe,
            nom=payload.nom,
            description=payload.description,
            niveau=payload.niveau,
            categorie=payload.categorie,
            statut=payload.statut
        )
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_regle_detection == id_regle
        )
    ).first()

    return row_to_dict(row)


@router.get(
    "",
    dependencies=[Depends(require_permission("ALERT_READ"))]
)
def list_regles(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    t = get_table(db)

    total = db.execute(
        select(func.count()).select_from(t)
    ).scalar_one()

    rows = db.execute(
        select(t)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).fetchall()

    pages = (
        (total + page_size - 1) // page_size
        if total > 0
        else 0
    )

    return {
        "items": [row_to_dict(row) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages
    }


@router.get(
    "/{id_regle_detection}",
    dependencies=[Depends(require_permission("ALERT_READ"))]
)
def get_regle(
    id_regle_detection: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    regle_id = uuid_to_bytes(id_regle_detection)

    row = db.execute(
        select(t).where(
            t.c.id_regle_detection == regle_id
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Règle de détection introuvable"
        )

    return row_to_dict(row)


@router.put(
    "/{id_regle_detection}",
    dependencies=[Depends(require_permission("ALERT_UPDATE"))]
)
def update_regle(
    id_regle_detection: str,
    payload: RegleDetectionUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    regle_id = uuid_to_bytes(id_regle_detection)

    existing = db.execute(
        select(t).where(
            t.c.id_regle_detection == regle_id
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Règle de détection introuvable"
        )

    values = payload.model_dump(exclude_unset=True)

    if not values:
        return row_to_dict(existing)

    if (
        "source" in values
        or "identifiant_externe" in values
    ):
        source = values.get(
            "source",
            existing._mapping["source"]
        )
        identifiant = values.get(
            "identifiant_externe",
            existing._mapping["identifiant_externe"]
        )

        duplicate = db.execute(
            select(t).where(
                t.c.source == source,
                t.c.identifiant_externe == identifiant,
                t.c.id_regle_detection != regle_id
            )
        ).first()

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="Une autre règle utilise déjà cette source et cet identifiant externe"
            )

    db.execute(
        update(t)
        .where(t.c.id_regle_detection == regle_id)
        .values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_regle_detection == regle_id
        )
    ).first()

    return row_to_dict(row)


@router.delete(
    "/{id_regle_detection}",
    dependencies=[Depends(require_permission("ALERT_DELETE"))]
)
def delete_regle(
    id_regle_detection: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    regle_id = uuid_to_bytes(id_regle_detection)

    result = db.execute(
        delete(t).where(
            t.c.id_regle_detection == regle_id
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Règle de détection introuvable"
        )

    db.commit()

    return {
        "message": "Règle de détection supprimée"
    }