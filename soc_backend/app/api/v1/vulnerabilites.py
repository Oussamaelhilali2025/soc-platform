import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, select, insert
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/vulnerabilite",
    tags=["vulnerabilite"]
)

md = MetaData()
_table = None


def get_table(db):
    global _table

    if _table is None:
        _table = Table(
            "vulnerabilite",
            md,
            autoload_with=db.bind
        )

    return _table


def normalize_value(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes=bytes(value)))

    if isinstance(value, Decimal):
        return float(value)

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return value


def row_to_dict(row):
    if row is None:
        return None

    return {
        key: normalize_value(value)
        for key, value in row._mapping.items()
    }


class VulnerabiliteCreate(BaseModel):
    cve: str | None = None
    nom: str
    description: str | None = None
    severite: str
    score_cvss: float | None = Field(
        default=None,
        ge=0,
        le=10
    )
    solution: str | None = None
    statut: str = "OPEN"


@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def create_vulnerabilite(
    payload: VulnerabiliteCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    vulnerabilite_id = uuid.uuid4().bytes

    values = {
        "id_vulnerabilite": vulnerabilite_id,
        "cve": payload.cve,
        "nom": payload.nom,
        "description": payload.description,
        "severite": payload.severite,
        "score_cvss": payload.score_cvss,
        "solution": payload.solution,
        "statut": payload.statut,
    }

    db.execute(
        insert(t).values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_vulnerabilite == vulnerabilite_id
        )
    ).first()

    return row_to_dict(row)