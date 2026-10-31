from datetime import datetime
import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evenement-reseau",
    tags=["evenement-reseau"]
)


PROTOCOLES = {
    "TCP",
    "UDP",
    "ICMP",
    "HTTP",
    "HTTPS",
    "DNS",
    "SSH",
    "FTP",
    "OTHER",
}

DIRECTIONS = {
    "INBOUND",
    "OUTBOUND",
    "INTERNAL",
}

ACTIONS_RESEAU = {
    "ALLOW",
    "BLOCK",
    "DROP",
    "REJECT",
    "ALERT",
    "OTHER",
}


class EvenementReseauCreate(BaseModel):
    id_evenement: uuid.UUID
    adresse_ip_source: str
    adresse_ip_destination: str
    port_source: int | None = None
    port_destination: int | None = None
    protocole: str | None = None
    direction: str | None = None
    action_reseau: str | None = None

    @field_validator("adresse_ip_source", "adresse_ip_destination")
    @classmethod
    def validate_ip(cls, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Adresse IP invalide")
        return value

    @field_validator("port_source", "port_destination")
    @classmethod
    def validate_port(cls, value):
        if value is not None and not 0 <= value <= 65535:
            raise ValueError("Le port doit être compris entre 0 et 65535")
        return value

    @field_validator("protocole")
    @classmethod
    def validate_protocole(cls, value):
        if value is not None and value not in PROTOCOLES:
            raise ValueError(
                "protocole doit être l'une des valeurs: "
                + ", ".join(sorted(PROTOCOLES))
            )
        return value

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, value):
        if value is not None and value not in DIRECTIONS:
            raise ValueError(
                "direction doit être l'une des valeurs: "
                + ", ".join(sorted(DIRECTIONS))
            )
        return value

    @field_validator("action_reseau")
    @classmethod
    def validate_action(cls, value):
        if value is not None and value not in ACTIONS_RESEAU:
            raise ValueError(
                "action_reseau doit être l'une des valeurs: "
                + ", ".join(sorted(ACTIONS_RESEAU))
            )
        return value


class EvenementReseauUpdate(BaseModel):
    adresse_ip_source: str | None = None
    adresse_ip_destination: str | None = None
    port_source: int | None = None
    port_destination: int | None = None
    protocole: str | None = None
    direction: str | None = None
    action_reseau: str | None = None

    @field_validator("adresse_ip_source", "adresse_ip_destination")
    @classmethod
    def validate_ip(cls, value):
        if value is None:
            return value
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Adresse IP invalide")
        return value

    @field_validator("port_source", "port_destination")
    @classmethod
    def validate_port(cls, value):
        if value is not None and not 0 <= value <= 65535:
            raise ValueError("Le port doit être compris entre 0 et 65535")
        return value

    @field_validator("protocole")
    @classmethod
    def validate_protocole(cls, value):
        if value is not None and value not in PROTOCOLES:
            raise ValueError(
                "protocole doit être l'une des valeurs: "
                + ", ".join(sorted(PROTOCOLES))
            )
        return value

    @field_validator("direction")
    @classmethod
    def validate_direction(cls, value):
        if value is not None and value not in DIRECTIONS:
            raise ValueError(
                "direction doit être l'une des valeurs: "
                + ", ".join(sorted(DIRECTIONS))
            )
        return value

    @field_validator("action_reseau")
    @classmethod
    def validate_action(cls, value):
        if value is not None and value not in ACTIONS_RESEAU:
            raise ValueError(
                "action_reseau doit être l'une des valeurs: "
                + ", ".join(sorted(ACTIONS_RESEAU))
            )
        return value


def serialize_row(row):
    result = {}

    for key, value in row.items():
        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            try:
                value = str(uuid.UUID(bytes=bytes(value)))
            except (ValueError, AttributeError):
                pass

        elif isinstance(value, datetime):
            value = value.isoformat()

        result[key] = value

    return result


def evenement_exists(db: Session, id_evenement: uuid.UUID):
    row = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement
            WHERE id_evenement = :id_evenement
            LIMIT 1
        """),
        {
            "id_evenement": id_evenement.bytes
        }
    ).first()

    return row is not None


@router.post("", status_code=201)
def create_evenement_reseau(
    body: EvenementReseauCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    data = body.model_dump()

    # L'événement parent doit exister
    if not evenement_exists(db, data["id_evenement"]):
        raise HTTPException(
            status_code=404,
            detail="Evenement parent not found"
        )

    # Un événement réseau ne peut avoir qu'une seule ligne
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_reseau
            WHERE id_evenement = :id_evenement
            LIMIT 1
        """),
        {
            "id_evenement": data["id_evenement"].bytes
        }
    ).first()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="Evenement reseau already exists for this evenement"
        )

    db.execute(
        text("""
            INSERT INTO evenement_reseau (
                id_evenement,
                adresse_ip_source,
                adresse_ip_destination,
                port_source,
                port_destination,
                protocole,
                direction,
                action_reseau
            )
            VALUES (
                :id_evenement,
                :adresse_ip_source,
                :adresse_ip_destination,
                :port_source,
                :port_destination,
                :protocole,
                :direction,
                :action_reseau
            )
        """),
        {
            "id_evenement": data["id_evenement"].bytes,
            "adresse_ip_source": data["adresse_ip_source"],
            "adresse_ip_destination": data["adresse_ip_destination"],
            "port_source": data["port_source"],
            "port_destination": data["port_destination"],
            "protocole": data["protocole"],
            "direction": data["direction"],
            "action_reseau": data["action_reseau"],
        }
    )

    db.commit()

    return {
        "id_evenement": str(data["id_evenement"]),
        "message": "Evenement reseau created successfully"
    }


@router.get("")
def list_evenements_reseau(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    offset = (page - 1) * page_size

    rows = db.execute(
        text("""
            SELECT *
            FROM evenement_reseau
            ORDER BY id_evenement
            LIMIT :limit OFFSET :offset
        """),
        {
            "limit": page_size,
            "offset": offset
        }
    ).mappings().all()

    total = db.execute(
        text("""
            SELECT COUNT(*)
            FROM evenement_reseau
        """)
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
        "pages": pages
    }


@router.get("/{item_id}")
def get_evenement_reseau(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    row = db.execute(
        text("""
            SELECT *
            FROM evenement_reseau
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="evenement reseau not found"
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_evenement_reseau(
    item_id: uuid.UUID,
    body: EvenementReseauUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    existing = db.execute(
        text("""
            SELECT *
            FROM evenement_reseau
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    ).mappings().first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement reseau not found"
        )

    updates = body.model_dump(exclude_unset=True)

    if not updates:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    allowed_fields = {
        "adresse_ip_source",
        "adresse_ip_destination",
        "port_source",
        "port_destination",
        "protocole",
        "direction",
        "action_reseau"
    }

    set_parts = []
    params = {
        "id_evenement": item_id.bytes
    }

    for key, value in updates.items():
        if key not in allowed_fields:
            continue

        set_parts.append(f"{key} = :{key}")
        params[key] = value

    if not set_parts:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    db.execute(
        text(f"""
            UPDATE evenement_reseau
            SET {", ".join(set_parts)}
            WHERE id_evenement = :id_evenement
        """),
        params
    )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement reseau updated successfully"
    }


@router.delete("/{item_id}")
def delete_evenement_reseau(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    result = db.execute(
        text("""
            DELETE FROM evenement_reseau
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="evenement reseau not found"
        )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement reseau deleted successfully"
    }