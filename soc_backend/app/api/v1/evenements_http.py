from datetime import datetime
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evenement-http",
    tags=["evenement-http"]
)


class EvenementHttpCreate(BaseModel):
    id_evenement: uuid.UUID
    methode_http: str | None = None
    url: str | None = None
    uri: str | None = None
    hostname: str | None = None
    port: int | None = None
    code_statut: int | None = None
    taille_reponse: int | None = None
    headers_reponse: dict | None = None
    referer: str | None = None
    user_agent: str | None = None
    payload: str | None = None

    @field_validator("methode_http")
    @classmethod
    def validate_methode_http(cls, value):
        if value is not None and len(value) > 10:
            raise ValueError(
                "methode_http ne peut pas dépasser 10 caractères"
            )
        return value

    @field_validator("port")
    @classmethod
    def validate_port(cls, value):
        if value is not None and not 0 <= value <= 65535:
            raise ValueError(
                "Le port doit être compris entre 0 et 65535"
            )
        return value

    @field_validator("code_statut")
    @classmethod
    def validate_code_statut(cls, value):
        if value is not None and not 100 <= value <= 599:
            raise ValueError(
                "code_statut doit être compris entre 100 et 599"
            )
        return value

    @field_validator("taille_reponse")
    @classmethod
    def validate_taille_reponse(cls, value):
        if value is not None and value < 0:
            raise ValueError(
                "taille_reponse ne peut pas être négative"
            )
        return value


class EvenementHttpUpdate(BaseModel):
    methode_http: str | None = None
    url: str | None = None
    uri: str | None = None
    hostname: str | None = None
    port: int | None = None
    code_statut: int | None = None
    taille_reponse: int | None = None
    headers_reponse: dict | None = None
    referer: str | None = None
    user_agent: str | None = None
    payload: str | None = None

    @field_validator("methode_http")
    @classmethod
    def validate_methode_http(cls, value):
        if value is not None and len(value) > 10:
            raise ValueError(
                "methode_http ne peut pas dépasser 10 caractères"
            )
        return value

    @field_validator("port")
    @classmethod
    def validate_port(cls, value):
        if value is not None and not 0 <= value <= 65535:
            raise ValueError(
                "Le port doit être compris entre 0 et 65535"
            )
        return value

    @field_validator("code_statut")
    @classmethod
    def validate_code_statut(cls, value):
        if value is not None and not 100 <= value <= 599:
            raise ValueError(
                "code_statut doit être compris entre 100 et 599"
            )
        return value

    @field_validator("taille_reponse")
    @classmethod
    def validate_taille_reponse(cls, value):
        if value is not None and value < 0:
            raise ValueError(
                "taille_reponse ne peut pas être négative"
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

        elif key == "headers_reponse":
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass

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
def create_evenement_http(
    body: EvenementHttpCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    data = body.model_dump()

    # Vérifier l'événement parent
    if not evenement_exists(db, data["id_evenement"]):
        raise HTTPException(
            status_code=404,
            detail="Evenement parent not found"
        )

    # Un événement ne peut avoir qu'un seul sous-type HTTP
    existing = db.execute(
        text("""
            SELECT id_evenement
            FROM evenement_http
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
            detail="Evenement HTTP already exists for this evenement"
        )

    headers_json = None

    if data["headers_reponse"] is not None:
        headers_json = json.dumps(
            data["headers_reponse"],
            ensure_ascii=False
        )

    db.execute(
        text("""
            INSERT INTO evenement_http (
                id_evenement,
                methode_http,
                url,
                uri,
                hostname,
                port,
                code_statut,
                taille_reponse,
                headers_reponse,
                referer,
                user_agent,
                payload
            )
            VALUES (
                :id_evenement,
                :methode_http,
                :url,
                :uri,
                :hostname,
                :port,
                :code_statut,
                :taille_reponse,
                :headers_reponse,
                :referer,
                :user_agent,
                :payload
            )
        """),
        {
            "id_evenement": data["id_evenement"].bytes,
            "methode_http": data["methode_http"],
            "url": data["url"],
            "uri": data["uri"],
            "hostname": data["hostname"],
            "port": data["port"],
            "code_statut": data["code_statut"],
            "taille_reponse": data["taille_reponse"],
            "headers_reponse": headers_json,
            "referer": data["referer"],
            "user_agent": data["user_agent"],
            "payload": data["payload"],
        }
    )

    db.commit()

    return {
        "id_evenement": str(data["id_evenement"]),
        "message": "Evenement HTTP created successfully"
    }


@router.get("")
def list_evenements_http(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    offset = (page - 1) * page_size

    rows = db.execute(
        text("""
            SELECT *
            FROM evenement_http
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
            FROM evenement_http
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
def get_evenement_http(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    row = db.execute(
        text("""
            SELECT *
            FROM evenement_http
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="evenement HTTP not found"
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_evenement_http(
    item_id: uuid.UUID,
    body: EvenementHttpUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    existing = db.execute(
        text("""
            SELECT *
            FROM evenement_http
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    ).mappings().first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement HTTP not found"
        )

    updates = body.model_dump(exclude_unset=True)

    if not updates:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    allowed_fields = {
        "methode_http",
        "url",
        "uri",
        "hostname",
        "port",
        "code_statut",
        "taille_reponse",
        "headers_reponse",
        "referer",
        "user_agent",
        "payload"
    }

    set_parts = []
    params = {
        "id_evenement": item_id.bytes
    }

    for key, value in updates.items():

        if key not in allowed_fields:
            continue

        if key == "headers_reponse":
            params[key] = (
                json.dumps(value, ensure_ascii=False)
                if value is not None
                else None
            )
        else:
            params[key] = value

        set_parts.append(f"{key} = :{key}")

    if not set_parts:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    db.execute(
        text(f"""
            UPDATE evenement_http
            SET {", ".join(set_parts)}
            WHERE id_evenement = :id_evenement
        """),
        params
    )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement HTTP updated successfully"
    }


@router.delete("/{item_id}")
def delete_evenement_http(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    result = db.execute(
        text("""
            DELETE FROM evenement_http
            WHERE id_evenement = :id_evenement
        """),
        {
            "id_evenement": item_id.bytes
        }
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="evenement HTTP not found"
        )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement HTTP deleted successfully"
    }