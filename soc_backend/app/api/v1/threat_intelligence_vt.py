from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/threat-intelligence-vt",
    tags=["threat_intelligence_vt"],
)


class ThreatIntelligenceVTCreate(BaseModel):
    id_ioc: uuid.UUID
    malicious_count: int = Field(default=0, ge=0)
    suspicious_count: int = Field(default=0, ge=0)
    harmless_count: int = Field(default=0, ge=0)
    undetected_count: int = Field(default=0, ge=0)
    total_engines: int = Field(ge=0)
    reputation: int | None = None
    last_analysis_date: datetime
    permalink: str | None = None
    raw_response: str | None = None


class ThreatIntelligenceVTUpdate(BaseModel):
    malicious_count: int | None = Field(default=None, ge=0)
    suspicious_count: int | None = Field(default=None, ge=0)
    harmless_count: int | None = Field(default=None, ge=0)
    undetected_count: int | None = Field(default=None, ge=0)
    total_engines: int | None = Field(default=None, ge=0)
    reputation: int | None = None
    last_analysis_date: datetime | None = None
    permalink: str | None = None
    raw_response: str | None = None


def serialize_row(row):
    result = {}

    for key, value in row.items():
        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            value = str(uuid.UUID(bytes=bytes(value)))
        elif isinstance(value, datetime):
            value = value.isoformat()

        result[key] = value

    return result


@router.post("", status_code=201)
def create_threat_intelligence_vt(
    body: ThreatIntelligenceVTCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_CREATE")),
):
    # Vérifier que l'IOC existe
    ioc = db.execute(
        text(
            """
            SELECT id_ioc
            FROM ioc
            WHERE id_ioc = :id_ioc
            """
        ),
        {"id_ioc": body.id_ioc.bytes},
    ).first()

    if not ioc:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    # Un seul résultat VirusTotal par IOC
    existing = db.execute(
        text(
            """
            SELECT id_ti_vt
            FROM threat_intelligence_vt
            WHERE id_ioc = :id_ioc
            """
        ),
        {"id_ioc": body.id_ioc.bytes},
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="VirusTotal intelligence already exists for this IOC",
        )

    ti_id = uuid.uuid4()

    db.execute(
        text(
            """
            INSERT INTO threat_intelligence_vt (
                id_ti_vt,
                id_ioc,
                malicious_count,
                suspicious_count,
                harmless_count,
                undetected_count,
                total_engines,
                reputation,
                last_analysis_date,
                permalink,
                raw_response
            )
            VALUES (
                :id_ti_vt,
                :id_ioc,
                :malicious_count,
                :suspicious_count,
                :harmless_count,
                :undetected_count,
                :total_engines,
                :reputation,
                :last_analysis_date,
                :permalink,
                :raw_response
            )
            """
        ),
        {
            "id_ti_vt": ti_id.bytes,
            "id_ioc": body.id_ioc.bytes,
            "malicious_count": body.malicious_count,
            "suspicious_count": body.suspicious_count,
            "harmless_count": body.harmless_count,
            "undetected_count": body.undetected_count,
            "total_engines": body.total_engines,
            "reputation": body.reputation,
            "last_analysis_date": body.last_analysis_date,
            "permalink": body.permalink,
            "raw_response": body.raw_response,
        },
    )

    db.commit()

    return {
        "id_ti_vt": str(ti_id),
        "message": "VirusTotal intelligence created successfully",
    }


@router.get("")
def list_threat_intelligence_vt(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    if page < 1:
        raise HTTPException(422, "page must be >= 1")

    if page_size < 1 or page_size > 200:
        raise HTTPException(
            422,
            "page_size must be between 1 and 200",
        )

    offset = (page - 1) * page_size

    rows = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_vt
            ORDER BY last_analysis_date DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {
            "limit": page_size,
            "offset": offset,
        },
    ).mappings().all()

    total = db.execute(
        text(
            "SELECT COUNT(*) FROM threat_intelligence_vt"
        )
    ).scalar_one()

    pages = (
        (total + page_size - 1) // page_size
        if total > 0
        else 0
    )

    return {
        "items": [
            serialize_row(row)
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get("/{item_id}")
def get_threat_intelligence_vt(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    row = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_vt
            WHERE id_ti_vt = :id
            """
        ),
        {"id": item_id.bytes},
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="VirusTotal intelligence not found",
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_threat_intelligence_vt(
    item_id: uuid.UUID,
    body: ThreatIntelligenceVTUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_CREATE")),
):
    existing = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_vt
            WHERE id_ti_vt = :id
            """
        ),
        {"id": item_id.bytes},
    ).mappings().first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="VirusTotal intelligence not found",
        )

    updates = body.model_dump(exclude_unset=True)

    if not updates:
        return {
            "id_ti_vt": str(item_id),
            "message": "No changes",
        }

    set_parts = []
    params = {"id": item_id.bytes}

    allowed_fields = {
        "malicious_count",
        "suspicious_count",
        "harmless_count",
        "undetected_count",
        "total_engines",
        "reputation",
        "last_analysis_date",
        "permalink",
        "raw_response",
    }

    for key, value in updates.items():
        if key in allowed_fields:
            set_parts.append(f"{key} = :{key}")
            params[key] = value

    if not set_parts:
        return {
            "id_ti_vt": str(item_id),
            "message": "No changes",
        }

    db.execute(
        text(
            f"""
            UPDATE threat_intelligence_vt
            SET {", ".join(set_parts)}
            WHERE id_ti_vt = :id
            """
        ),
        params,
    )

    db.commit()

    return {
        "id_ti_vt": str(item_id),
        "message": "VirusTotal intelligence updated successfully",
    }


@router.delete("/{item_id}")
def delete_threat_intelligence_vt(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_CREATE")),
):
    result = db.execute(
        text(
            """
            DELETE FROM threat_intelligence_vt
            WHERE id_ti_vt = :id
            """
        ),
        {"id": item_id.bytes},
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="VirusTotal intelligence not found",
        )

    db.commit()

    return {
        "id_ti_vt": str(item_id),
        "message": "VirusTotal intelligence deleted successfully",
    }