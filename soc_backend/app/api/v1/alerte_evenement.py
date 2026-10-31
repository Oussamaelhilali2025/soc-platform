import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, select, insert, update, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/alerte-evenement",
    tags=["alerte-evenement"]
)

md = MetaData()
_table = None
_alerte_table = None
_evenement_table = None


def get_table(db: Session):
    global _table

    if _table is None:
        _table = Table(
            "alerte_evenement",
            md,
            autoload_with=db.bind
        )

    return _table


def get_alerte_table(db: Session):
    global _alerte_table

    if _alerte_table is None:
        _alerte_table = Table(
            "alerte",
            md,
            autoload_with=db.bind
        )

    return _alerte_table


def get_evenement_table(db: Session):
    global _evenement_table

    if _evenement_table is None:
        _evenement_table = Table(
            "evenement",
            md,
            autoload_with=db.bind
        )

    return _evenement_table


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
    if row is None:
        return None

    data = dict(row._mapping)

    if "id_alerte" in data:
        data["id_alerte"] = normalize_uuid(
            data["id_alerte"]
        )

    if "id_evenement" in data:
        data["id_evenement"] = normalize_uuid(
            data["id_evenement"]
        )

    return data


class AlerteEvenementCreate(BaseModel):
    id_alerte: str
    id_evenement: str
    role_evenement: str | None = Field(
        default=None,
        max_length=50
    )


class AlerteEvenementUpdate(BaseModel):
    role_evenement: str | None = Field(
        default=None,
        max_length=50
    )


@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_permission("ALERT_CREATE"))
    ]
)
def create_relation(
    payload: AlerteEvenementCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    id_alerte = uuid_to_bytes(payload.id_alerte)
    id_evenement = uuid_to_bytes(payload.id_evenement)

    alerte_table = get_alerte_table(db)
    evenement_table = get_evenement_table(db)

    # Vérifier que l'alerte existe
    alerte = db.execute(
        select(alerte_table).where(
            alerte_table.c.id_alerte == id_alerte
        )
    ).first()

    if not alerte:
        raise HTTPException(
            status_code=404,
            detail="Alerte introuvable"
        )

    # Vérifier que l'événement existe
    evenement = db.execute(
        select(evenement_table).where(
            evenement_table.c.id_evenement == id_evenement
        )
    ).first()

    if not evenement:
        raise HTTPException(
            status_code=404,
            detail="Événement introuvable"
        )

    # Vérifier si la relation existe déjà
    existing = db.execute(
        select(t).where(
            (t.c.id_alerte == id_alerte)
            &
            (t.c.id_evenement == id_evenement)
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="La relation alerte/événement existe déjà"
        )

    # Création
    db.execute(
        insert(t).values(
            id_alerte=id_alerte,
            id_evenement=id_evenement,
            role_evenement=payload.role_evenement
        )
    )

    db.commit()

    # Récupération de la relation créée
    row = db.execute(
        select(t).where(
            (t.c.id_alerte == id_alerte)
            &
            (t.c.id_evenement == id_evenement)
        )
    ).first()

    return row_to_dict(row)


@router.get(
    "/{id_alerte}/{id_evenement}",
    dependencies=[
        Depends(require_permission("ALERT_READ"))
    ]
)
def get_relation(
    id_alerte: str,
    id_evenement: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    alerte_id = uuid_to_bytes(id_alerte)
    evenement_id = uuid_to_bytes(id_evenement)

    row = db.execute(
        select(t).where(
            (t.c.id_alerte == alerte_id)
            &
            (t.c.id_evenement == evenement_id)
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Relation alerte/événement introuvable"
        )

    return row_to_dict(row)


@router.put(
    "/{id_alerte}/{id_evenement}",
    dependencies=[
        Depends(require_permission("ALERT_UPDATE"))
    ]
)
def update_relation(
    id_alerte: str,
    id_evenement: str,
    payload: AlerteEvenementUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    alerte_id = uuid_to_bytes(id_alerte)
    evenement_id = uuid_to_bytes(id_evenement)

    # Vérifier que la relation existe
    existing = db.execute(
        select(t).where(
            (t.c.id_alerte == alerte_id)
            &
            (t.c.id_evenement == evenement_id)
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Relation alerte/événement introuvable"
        )

    values = payload.model_dump(
        exclude_unset=True
    )

    if not values:
        return row_to_dict(existing)

    db.execute(
        update(t)
        .where(
            (t.c.id_alerte == alerte_id)
            &
            (t.c.id_evenement == evenement_id)
        )
        .values(**values)
    )

    db.commit()

    # Récupérer la relation mise à jour
    row = db.execute(
        select(t).where(
            (t.c.id_alerte == alerte_id)
            &
            (t.c.id_evenement == evenement_id)
        )
    ).first()

    return row_to_dict(row)


@router.delete(
    "/{id_alerte}/{id_evenement}",
    dependencies=[
        Depends(require_permission("ALERT_DELETE"))
    ]
)
def delete_relation(
    id_alerte: str,
    id_evenement: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    alerte_id = uuid_to_bytes(id_alerte)
    evenement_id = uuid_to_bytes(id_evenement)

    result = db.execute(
        delete(t).where(
            (t.c.id_alerte == alerte_id)
            &
            (t.c.id_evenement == evenement_id)
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Relation alerte/événement introuvable"
        )

    db.commit()

    return {
        "message": "Relation alerte/événement supprimée"
    }