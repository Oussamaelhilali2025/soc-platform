import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import MetaData, Table, select, insert, update, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/incident-ioc",
    tags=["incident-ioc"]
)

md = MetaData()

_table = None
_incident_table = None
_ioc_table = None
_utilisateur_table = None


def get_table(db):
    global _table
    if _table is None:
        _table = Table(
            "incident_ioc",
            md,
            autoload_with=db.bind
        )
    return _table


def get_incident_table(db):
    global _incident_table
    if _incident_table is None:
        _incident_table = Table(
            "incident",
            md,
            autoload_with=db.bind
        )
    return _incident_table


def get_ioc_table(db):
    global _ioc_table
    if _ioc_table is None:
        _ioc_table = Table(
            "ioc",
            md,
            autoload_with=db.bind
        )
    return _ioc_table


def get_utilisateur_table(db):
    global _utilisateur_table
    if _utilisateur_table is None:
        _utilisateur_table = Table(
            "utilisateur",
            md,
            autoload_with=db.bind
        )
    return _utilisateur_table


def uuid_to_bytes(value: str):
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

    for field in [
        "id_incident",
        "id_ioc",
        "id_utilisateur_ajout"
    ]:
        if field in data:
            data[field] = normalize_uuid(data[field])

    if "date_ajout" in data and data["date_ajout"] is not None:
        data["date_ajout"] = data["date_ajout"].isoformat()

    return data


class IncidentIocCreate(BaseModel):
    id_incident: str
    id_ioc: str
    role_ioc: str | None = None
    id_utilisateur_ajout: str


class IncidentIocUpdate(BaseModel):
    role_ioc: str | None = None
    id_utilisateur_ajout: str


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(require_permission("INCIDENT_CREATE"))]
)
def create_relation(
    payload: IncidentIocCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    incident_id = uuid_to_bytes(payload.id_incident)
    ioc_id = uuid_to_bytes(payload.id_ioc)
    utilisateur_id = uuid_to_bytes(payload.id_utilisateur_ajout)

    incident_table = get_incident_table(db)
    ioc_table = get_ioc_table(db)
    utilisateur_table = get_utilisateur_table(db)

    # Vérifier incident
    incident = db.execute(
        select(incident_table).where(
            incident_table.c.id_incident == incident_id
        )
    ).first()

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident introuvable"
        )

    # Vérifier IOC
    ioc = db.execute(
        select(ioc_table).where(
            ioc_table.c.id_ioc == ioc_id
        )
    ).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC introuvable"
        )

    # Vérifier utilisateur
    utilisateur = db.execute(
        select(utilisateur_table).where(
            utilisateur_table.c.id_utilisateur == utilisateur_id
        )
    ).first()

    if not utilisateur:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur introuvable"
        )

    # Vérifier doublon
    existing = db.execute(
        select(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="La relation incident/IOC existe déjà"
        )

    # Création
    db.execute(
        insert(t).values(
            id_incident=incident_id,
            id_ioc=ioc_id,
            role_ioc=payload.role_ioc,
            id_utilisateur_ajout=utilisateur_id
        )
    )

    db.commit()

    row = db.execute(
        select(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    ).first()

    return row_to_dict(row)


@router.get(
    "/{id_incident}/{id_ioc}",
    dependencies=[Depends(require_permission("INCIDENT_READ"))]
)
def get_relation(
    id_incident: str,
    id_ioc: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    incident_id = uuid_to_bytes(id_incident)
    ioc_id = uuid_to_bytes(id_ioc)

    row = db.execute(
        select(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Relation incident/IOC introuvable"
        )

    return row_to_dict(row)


@router.put(
    "/{id_incident}/{id_ioc}",
    dependencies=[Depends(require_permission("INCIDENT_UPDATE"))]
)
def update_relation(
    id_incident: str,
    id_ioc: str,
    payload: IncidentIocUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    incident_id = uuid_to_bytes(id_incident)
    ioc_id = uuid_to_bytes(id_ioc)
    utilisateur_id = uuid_to_bytes(payload.id_utilisateur_ajout)

    utilisateur_table = get_utilisateur_table(db)

    # Vérifier utilisateur
    utilisateur = db.execute(
        select(utilisateur_table).where(
            utilisateur_table.c.id_utilisateur == utilisateur_id
        )
    ).first()

    if not utilisateur:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur introuvable"
        )

    # Vérifier relation
    existing = db.execute(
        select(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Relation incident/IOC introuvable"
        )

    db.execute(
        update(t)
        .where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
        .values(
            role_ioc=payload.role_ioc,
            id_utilisateur_ajout=utilisateur_id
        )
    )

    db.commit()

    row = db.execute(
        select(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    ).first()

    return row_to_dict(row)


@router.delete(
    "/{id_incident}/{id_ioc}",
    dependencies=[Depends(require_permission("INCIDENT_CLOSE"))]
)
def delete_relation(
    id_incident: str,
    id_ioc: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    incident_id = uuid_to_bytes(id_incident)
    ioc_id = uuid_to_bytes(id_ioc)

    result = db.execute(
        delete(t).where(
            (t.c.id_incident == incident_id)
            & (t.c.id_ioc == ioc_id)
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Relation incident/IOC introuvable"
        )

    db.commit()

    return {
        "message": "Relation incident/IOC supprimée"
    }