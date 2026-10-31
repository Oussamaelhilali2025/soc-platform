import uuid
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import MetaData, Table, select, insert, update, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/resultat-vulnerabilite",
    tags=["resultat-vulnerabilite"]
)

md = MetaData()

_table = None
_scan_table = None
_actif_table = None
_vulnerabilite_table = None


def get_table(db):
    global _table

    if _table is None:
        _table = Table(
            "resultat_vulnerabilite",
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


def get_vulnerabilite_table(db):
    global _vulnerabilite_table

    if _vulnerabilite_table is None:
        _vulnerabilite_table = Table(
            "vulnerabilite",
            md,
            autoload_with=db.bind
        )

    return _vulnerabilite_table


def uuid_to_bytes(value: str):
    try:
        return uuid.UUID(str(value)).bytes
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=f"UUID invalide: {value}"
        )


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


# ============================================================
# SCHEMA
# ============================================================

class ResultatVulnerabiliteCreate(BaseModel):
    id_scan: str
    id_actif: str
    id_vulnerabilite: str
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535
    )
    protocole: str | None = None
    score_cvss: float | None = Field(
        default=None,
        ge=0,
        le=10
    )
    severite: str | None = None
    preuve: str | None = None
    solution: str | None = None
    statut: str = "DETECTED"


class ResultatVulnerabiliteUpdate(BaseModel):
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535
    )
    protocole: str | None = None
    score_cvss: float | None = Field(
        default=None,
        ge=0,
        le=10
    )
    severite: str | None = None
    preuve: str | None = None
    solution: str | None = None
    statut: str = "DETECTED"


# ============================================================
# GET TOUS LES RÉSULTATS
# ============================================================

@router.get(
    "",
    dependencies=[
        Depends(require_permission("SCAN_READ"))
    ]
)
def list_resultats(
    db: Session = Depends(get_db)
):
    t = get_table(db)
    scan_table = get_scan_table(db)
    actif_table = get_actif_table(db)
    vulnerabilite_table = get_vulnerabilite_table(db)

    query = (
        select(
            t,
            scan_table.c.nom.label("scan_nom"),
            scan_table.c.cible.label("scan_cible"),
            scan_table.c.statut.label("scan_statut"),

            actif_table.c.nom.label("actif_nom"),
            actif_table.c.adresse_ip.label("actif_ip"),
            actif_table.c.hostname.label("actif_hostname"),

            vulnerabilite_table.c.cve.label("cve"),
            vulnerabilite_table.c.nom.label(
                "vulnerabilite_nom"
            ),
            vulnerabilite_table.c.description.label(
                "vulnerabilite_description"
            ),
            vulnerabilite_table.c.statut.label(
                "vulnerabilite_statut"
            ),
        )
        .join(
            scan_table,
            t.c.id_scan == scan_table.c.id_scan
        )
        .join(
            actif_table,
            t.c.id_actif == actif_table.c.id_actif
        )
        .join(
            vulnerabilite_table,
            t.c.id_vulnerabilite
            == vulnerabilite_table.c.id_vulnerabilite
        )
        .order_by(
            t.c.date_detection.desc()
        )
    )

    rows = db.execute(query).all()

    results = []

    for row in rows:
        results.append({
            key: normalize_value(value)
            for key, value in row._mapping.items()
        })

    return {
        "status": "ok",
        "count": len(results),
        "results": results
    }


# ============================================================
# GET UN RÉSULTAT
# ============================================================

@router.get(
    "/{resultat_id}",
    dependencies=[
        Depends(require_permission("SCAN_READ"))
    ]
)
def get_resultat(
    resultat_id: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    result_id = uuid_to_bytes(resultat_id)

    row = db.execute(
        select(t).where(
            t.c.id_resultat == result_id
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Résultat de vulnérabilité introuvable"
        )

    return row_to_dict(row)


# ============================================================
# CREATE
# ============================================================

@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def create_resultat(
    payload: ResultatVulnerabiliteCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    scan_id = uuid_to_bytes(payload.id_scan)
    actif_id = uuid_to_bytes(payload.id_actif)
    vulnerabilite_id = uuid_to_bytes(
        payload.id_vulnerabilite
    )

    scan_table = get_scan_table(db)
    actif_table = get_actif_table(db)
    vulnerabilite_table = get_vulnerabilite_table(db)

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

    vulnerabilite = db.execute(
        select(vulnerabilite_table).where(
            vulnerabilite_table.c.id_vulnerabilite
            == vulnerabilite_id
        )
    ).first()

    if not vulnerabilite:
        raise HTTPException(
            status_code=404,
            detail="Vulnérabilité introuvable"
        )

    result_id = uuid.uuid4().bytes

    values = {
        "id_resultat": result_id,
        "id_scan": scan_id,
        "id_actif": actif_id,
        "id_vulnerabilite": vulnerabilite_id,
        "port": payload.port,
        "protocole": payload.protocole,
        "score_cvss": payload.score_cvss,
        "severite": payload.severite,
        "preuve": payload.preuve,
        "solution": payload.solution,
        "statut": payload.statut,
    }

    db.execute(
        insert(t).values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_resultat == result_id
        )
    ).first()

    return row_to_dict(row)


# ============================================================
# UPDATE
# ============================================================

@router.put(
    "/{resultat_id}",
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def update_resultat(
    resultat_id: str,
    payload: ResultatVulnerabiliteUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    result_id = uuid_to_bytes(resultat_id)

    existing = db.execute(
        select(t).where(
            t.c.id_resultat == result_id
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Résultat de vulnérabilité introuvable"
        )

    values = {
        "port": payload.port,
        "protocole": payload.protocole,
        "score_cvss": payload.score_cvss,
        "severite": payload.severite,
        "preuve": payload.preuve,
        "solution": payload.solution,
        "statut": payload.statut,
    }

    db.execute(
        update(t)
        .where(
            t.c.id_resultat == result_id
        )
        .values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_resultat == result_id
        )
    ).first()

    return row_to_dict(row)


# ============================================================
# DELETE
# ============================================================

@router.delete(
    "/{resultat_id}",
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def delete_resultat(
    resultat_id: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    result_id = uuid_to_bytes(resultat_id)

    existing = db.execute(
        select(t).where(
            t.c.id_resultat == result_id
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Résultat de vulnérabilité introuvable"
        )

    db.execute(
        delete(t).where(
            t.c.id_resultat == result_id
        )
    )

    db.commit()

    return {
        "status": "ok",
        "message": "Résultat supprimé",
        "id_resultat": resultat_id
    }