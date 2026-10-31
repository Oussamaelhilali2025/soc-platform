from datetime import datetime
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/threat-intelligence-abuseipdb",
    tags=["threat_intelligence_abuseipdb"],
)


class ThreatIntelligenceAbuseIPDBCreate(BaseModel):
    id_ioc: uuid.UUID
    abuse_confidence_score: int = Field(ge=0, le=100)
    total_reports: int = Field(default=0, ge=0)
    num_distinct_users: int = Field(default=0, ge=0)
    country_code: str | None = None
    country_name: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    is_tor: bool = False
    last_reported_at: datetime | None = None
    checked_at: datetime
    raw_response: str | None = None


class ThreatIntelligenceAbuseIPDBUpdate(BaseModel):
    abuse_confidence_score: int | None = Field(default=None, ge=0, le=100)
    total_reports: int | None = Field(default=None, ge=0)
    num_distinct_users: int | None = Field(default=None, ge=0)
    country_code: str | None = None
    country_name: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    is_tor: bool | None = None
    last_reported_at: datetime | None = None
    checked_at: datetime | None = None
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
def create_threat_intelligence_abuseipdb(
    body: ThreatIntelligenceAbuseIPDBCreate,
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

    # Un seul résultat AbuseIPDB par IOC
    existing = db.execute(
        text(
            """
            SELECT id_ti_abuse
            FROM threat_intelligence_abuseipdb
            WHERE id_ioc = :id_ioc
            """
        ),
        {"id_ioc": body.id_ioc.bytes},
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="AbuseIPDB intelligence already exists for this IOC",
        )

    ti_id = uuid.uuid4()

    db.execute(
        text(
            """
            INSERT INTO threat_intelligence_abuseipdb (
                id_ti_abuse,
                id_ioc,
                abuse_confidence_score,
                total_reports,
                num_distinct_users,
                country_code,
                country_name,
                isp,
                usage_type,
                is_tor,
                last_reported_at,
                checked_at,
                raw_response
            )
            VALUES (
                :id_ti_abuse,
                :id_ioc,
                :abuse_confidence_score,
                :total_reports,
                :num_distinct_users,
                :country_code,
                :country_name,
                :isp,
                :usage_type,
                :is_tor,
                :last_reported_at,
                :checked_at,
                :raw_response
            )
            """
        ),
        {
            "id_ti_abuse": ti_id.bytes,
            "id_ioc": body.id_ioc.bytes,
            "abuse_confidence_score": body.abuse_confidence_score,
            "total_reports": body.total_reports,
            "num_distinct_users": body.num_distinct_users,
            "country_code": body.country_code,
            "country_name": body.country_name,
            "isp": body.isp,
            "usage_type": body.usage_type,
            "is_tor": body.is_tor,
            "last_reported_at": body.last_reported_at,
            "checked_at": body.checked_at,
            "raw_response": body.raw_response,
        },
    )

    db.commit()

    return {
        "id_ti_abuse": str(ti_id),
        "message": "AbuseIPDB intelligence created successfully",
    }


@router.get("")
def list_threat_intelligence_abuseipdb(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    if page < 1:
        raise HTTPException(
            status_code=422,
            detail="page must be >= 1",
        )

    if page_size < 1 or page_size > 200:
        raise HTTPException(
            status_code=422,
            detail="page_size must be between 1 and 200",
        )

    offset = (page - 1) * page_size

    rows = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_abuseipdb
            ORDER BY checked_at DESC
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
            "SELECT COUNT(*) FROM threat_intelligence_abuseipdb"
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
def get_threat_intelligence_abuseipdb(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    row = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_abuseipdb
            WHERE id_ti_abuse = :id
            """
        ),
        {"id": item_id.bytes},
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="AbuseIPDB intelligence not found",
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_threat_intelligence_abuseipdb(
    item_id: uuid.UUID,
    body: ThreatIntelligenceAbuseIPDBUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_CREATE")),
):
    existing = db.execute(
        text(
            """
            SELECT *
            FROM threat_intelligence_abuseipdb
            WHERE id_ti_abuse = :id
            """
        ),
        {"id": item_id.bytes},
    ).mappings().first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="AbuseIPDB intelligence not found",
        )

    updates = body.model_dump(exclude_unset=True)

    if not updates:
        return {
            "id_ti_abuse": str(item_id),
            "message": "No changes",
        }

    allowed_fields = {
        "abuse_confidence_score",
        "total_reports",
        "num_distinct_users",
        "country_code",
        "country_name",
        "isp",
        "usage_type",
        "is_tor",
        "last_reported_at",
        "checked_at",
        "raw_response",
    }

    set_parts = []
    params = {"id": item_id.bytes}

    for key, value in updates.items():
        if key in allowed_fields:
            set_parts.append(f"{key} = :{key}")
            params[key] = value

    if not set_parts:
        return {
            "id_ti_abuse": str(item_id),
            "message": "No changes",
        }

    db.execute(
        text(
            f"""
            UPDATE threat_intelligence_abuseipdb
            SET {", ".join(set_parts)}
            WHERE id_ti_abuse = :id
            """
        ),
        params,
    )

    db.commit()

    return {
        "id_ti_abuse": str(item_id),
        "message": "AbuseIPDB intelligence updated successfully",
    }


@router.delete("/{item_id}")
def delete_threat_intelligence_abuseipdb(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_CREATE")),
):
    result = db.execute(
        text(
            """
            DELETE FROM threat_intelligence_abuseipdb
            WHERE id_ti_abuse = :id
            """
        ),
        {"id": item_id.bytes},
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="AbuseIPDB intelligence not found",
        )

    db.commit()

    return {
        "id_ti_abuse": str(item_id),
        "message": "AbuseIPDB intelligence deleted successfully",
    }