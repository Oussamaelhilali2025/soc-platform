import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import MetaData, Table, select, insert, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/scan-actif",
    tags=["scan-actif"]
)

md = MetaData()

_table = None
_scan_table = None
_actif_table = None


def get_table(db):
    global _table
    if _table is None:
        _table = Table(
            "scan_actif",
            md,
            autoload_with=db.bind
        )
    return _table


def get_scan_table(db):
    global _scan_table
    if _scan_table is None:
        _scan_table = Table(
            "scan_vulnerabilite",
            md,
            autoload_with=db.bind
        )
    return _scan_table


def get_actif_table(db):
    global _actif_table
    if _actif_table is None:
        _actif_table = Table(
            "actif",
            md,
            autoload_with=db.bind
        )
    return _actif_table


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

    for field in ["id_scan", "id_actif"]:
        if field in data:
            data[field] = normalize_uuid(data[field])

    return data


class ScanActifCreate(BaseModel):
    id_scan: str
    id_actif: str


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(require_permission("SCAN_CREATE"))]
)
def create_relation(
    payload: ScanActifCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    scan_id = uuid_to_bytes(payload.id_scan)
    actif_id = uuid_to_bytes(payload.id_actif)

    scan_table = get_scan_table(db)
    actif_table = get_actif_table(db)

    scan = db.execute(
        select(scan_table).where(
            scan_table.c.id_scan == scan_id
        )
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan introuvable"
        )

    actif = db.execute(
        select(actif_table).where(
            actif_table.c.id_actif == actif_id
        )
    ).first()

    if not actif:
        raise HTTPException(
            status_code=404,
            detail="Actif introuvable"
        )

    existing = db.execute(
        select(t).where(
            (t.c.id_scan == scan_id)
            & (t.c.id_actif == actif_id)
        )
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="La relation scan/actif existe déjà"
        )

    db.execute(
        insert(t).values(
            id_scan=scan_id,
            id_actif=actif_id
        )
    )

    db.commit()

    row = db.execute(
        select(t).where(
            (t.c.id_scan == scan_id)
            & (t.c.id_actif == actif_id)
        )
    ).first()

    return row_to_dict(row)


@router.get(
    "/{id_scan}/{id_actif}",
    dependencies=[Depends(require_permission("SCAN_READ"))]
)
def get_relation(
    id_scan: str,
    id_actif: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    scan_id = uuid_to_bytes(id_scan)
    actif_id = uuid_to_bytes(id_actif)

    row = db.execute(
        select(t).where(
            (t.c.id_scan == scan_id)
            & (t.c.id_actif == actif_id)
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Relation scan/actif introuvable"
        )

    return row_to_dict(row)


@router.delete(
    "/{id_scan}/{id_actif}",
    dependencies=[Depends(require_permission("SCAN_CREATE"))]
)
def delete_relation(
    id_scan: str,
    id_actif: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    scan_id = uuid_to_bytes(id_scan)
    actif_id = uuid_to_bytes(id_actif)

    result = db.execute(
        delete(t).where(
            (t.c.id_scan == scan_id)
            & (t.c.id_actif == actif_id)
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Relation scan/actif introuvable"
        )

    db.commit()

    return {
        "message": "Relation scan/actif supprimée"
    }