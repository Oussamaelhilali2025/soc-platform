from datetime import datetime, timezone
import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evenement",
    tags=["evenement"]
)


class EvenementCreate(BaseModel):
    id_agent: uuid.UUID 
    id_actif: uuid.UUID | None = None
    id_source: uuid.UUID

    identifiant_externe: str | None = None
    timestamp_evenement: datetime
    type_evenement: str
    categorie: str | None = None
    titre: str | None = None
    description: str | None = None
    severite: str | None = None
    niveau_wazuh: int | None = None
    rule_id_externe: str | None = None
    decoder: str | None = None
    utilisateur: str | None = None
    hostname: str | None = None
    localisation: str | None = None

    donnees_brutes: dict
    donnees_normalisees: dict | None = None


class EvenementUpdate(BaseModel):
    id_agent: uuid.UUID | None = None
    id_actif: uuid.UUID | None = None
    id_source: uuid.UUID | None = None

    identifiant_externe: str | None = None
    timestamp_evenement: datetime | None = None
    type_evenement: str | None = None
    categorie: str | None = None
    titre: str | None = None
    description: str | None = None
    severite: str | None = None
    niveau_wazuh: int | None = None
    rule_id_externe: str | None = None
    decoder: str | None = None
    utilisateur: str | None = None
    hostname: str | None = None
    localisation: str | None = None

    donnees_brutes: dict | None = None
    donnees_normalisees: dict | None = None


def serialize_row(row):
    result = {}

    for key, value in row.items():

        # BINARY(16) -> UUID
        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            try:
                value = str(uuid.UUID(bytes=bytes(value)))
            except (ValueError, AttributeError):
                pass

        # DATETIME -> ISO 8601
        elif isinstance(value, datetime):
            value = value.isoformat()

        # JSON stocké comme texte -> dict Python
        elif key in {"donnees_brutes", "donnees_normalisees"}:
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    pass

        result[key] = value

    return result


def validate_evenement(data):
    # type_evenement obligatoire
    if not data.get("type_evenement"):
        raise HTTPException(
            status_code=422,
            detail="type_evenement cannot be empty"
        )

    if not data["type_evenement"].strip():
        raise HTTPException(
            status_code=422,
            detail="type_evenement cannot be empty"
        )

    # donnees_brutes obligatoire
    if not data.get("donnees_brutes"):
        raise HTTPException(
            status_code=422,
            detail="donnees_brutes cannot be empty"
        )

    # niveau Wazuh : 0-15
    niveau = data.get("niveau_wazuh")

    if niveau is not None and not 0 <= niveau <= 15:
        raise HTTPException(
            status_code=422,
            detail="niveau_wazuh must be between 0 and 15"
        )


def uuid_bytes(value):
    """
    Convertit un UUID Python en BINARY(16)
    pour MariaDB.
    """
    if value is None:
        return None

    if isinstance(value, uuid.UUID):
        return value.bytes

    return uuid.UUID(str(value)).bytes


@router.post("", status_code=201)
def create_evenement(
    body: EvenementCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    data = body.model_dump()

    validate_evenement(data)

    evenement_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    # Vérification de la source
    source_exists = db.execute(
        text("""
            SELECT id_source
            FROM source_donnees
            WHERE id_source = :id_source
            LIMIT 1
        """),
        {
            "id_source": uuid_bytes(data["id_source"])
        }
    ).first()

    if not source_exists:
        raise HTTPException(
            status_code=404,
            detail="Source de données not found"
        )

    # Vérification agent si fourni
    if data["id_agent"] is not None:

        agent_exists = db.execute(
            text("""
                SELECT id_agent
                FROM agent
                WHERE id_agent = :id_agent
                LIMIT 1
            """),
            {
                "id_agent": uuid_bytes(data["id_agent"])
            }
        ).first()

        if not agent_exists:
            raise HTTPException(
                status_code=404,
                detail="Agent not found"
            )

    # Vérification actif si fourni
    if data["id_actif"] is not None:

        actif_exists = db.execute(
            text("""
                SELECT id_actif
                FROM actif
                WHERE id_actif = :id_actif
                LIMIT 1
            """),
            {
                "id_actif": uuid_bytes(data["id_actif"])
            }
        ).first()

        if not actif_exists:
            raise HTTPException(
                status_code=404,
                detail="Actif not found"
            )

    # Idempotence :
    # si identifiant_externe existe déjà pour la même source,
    # on évite de créer deux fois le même événement.
    if data["identifiant_externe"]:

        duplicate = db.execute(
            text("""
                SELECT id_evenement
                FROM evenement
                WHERE id_source = :id_source
                  AND identifiant_externe = :identifiant_externe
                LIMIT 1
            """),
            {
                "id_source": uuid_bytes(data["id_source"]),
                "identifiant_externe": data["identifiant_externe"]
            }
        ).first()

        if duplicate:
            existing_id = uuid.UUID(
                bytes=duplicate[0]
            )

            raise HTTPException(
                status_code=409,
                detail={
                    "message": "Evenement already exists",
                    "id_evenement": str(existing_id)
                }
            )

    # Conversion des JSON Python -> JSON texte
    donnees_brutes_json = json.dumps(
        data["donnees_brutes"],
        ensure_ascii=False
    )

    donnees_normalisees_json = None

    if data["donnees_normalisees"] is not None:
        donnees_normalisees_json = json.dumps(
            data["donnees_normalisees"],
            ensure_ascii=False
        )

    db.execute(
        text("""
            INSERT INTO evenement (
                id_evenement,
                id_agent,
                id_actif,
                id_source,
                identifiant_externe,
                timestamp_evenement,
                timestamp_reception,
                type_evenement,
                categorie,
                titre,
                description,
                severite,
                niveau_wazuh,
                rule_id_externe,
                decoder,
                utilisateur,
                hostname,
                localisation,
                donnees_brutes,
                donnees_normalisees
            )
            VALUES (
                :id_evenement,
                :id_agent,
                :id_actif,
                :id_source,
                :identifiant_externe,
                :timestamp_evenement,
                :timestamp_reception,
                :type_evenement,
                :categorie,
                :titre,
                :description,
                :severite,
                :niveau_wazuh,
                :rule_id_externe,
                :decoder,
                :utilisateur,
                :hostname,
                :localisation,
                :donnees_brutes,
                :donnees_normalisees
            )
        """),
        {
            "id_evenement": evenement_id.bytes,

            "id_agent": uuid_bytes(data["id_agent"])
            if data["id_agent"] else None,

            "id_actif": uuid_bytes(data["id_actif"])
            if data["id_actif"] else None,

            "id_source": uuid_bytes(data["id_source"]),

            "identifiant_externe": data["identifiant_externe"],

            "timestamp_evenement": data["timestamp_evenement"],

            "timestamp_reception": now,

            "type_evenement": data["type_evenement"],

            "categorie": data["categorie"],

            "titre": data["titre"],

            "description": data["description"],

            "severite": data["severite"],

            "niveau_wazuh": data["niveau_wazuh"],

            "rule_id_externe": data["rule_id_externe"],

            "decoder": data["decoder"],

            "utilisateur": data["utilisateur"],

            "hostname": data["hostname"],

            "localisation": data["localisation"],

            "donnees_brutes": donnees_brutes_json,

            "donnees_normalisees": donnees_normalisees_json
        }
    )

    db.commit()

    return {
        "id_evenement": str(evenement_id),
        "message": "Evenement created successfully"
    }


@router.get("")
def list_evenements(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    offset = (page - 1) * page_size

    rows = db.execute(
        text("""
            SELECT *
            FROM evenement
            ORDER BY timestamp_reception DESC
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
            FROM evenement
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
def get_evenement(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    row = db.execute(
        text("""
            SELECT *
            FROM evenement
            WHERE id_evenement = :id
        """),
        {
            "id": item_id.bytes
        }
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="evenement not found"
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_evenement(
    item_id: uuid.UUID,
    body: EvenementUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    existing = db.execute(
        text("""
            SELECT *
            FROM evenement
            WHERE id_evenement = :id
        """),
        {
            "id": item_id.bytes
        }
    ).mappings().first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="evenement not found"
        )

    updates = body.model_dump(
        exclude_unset=True
    )

    if not updates:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    # Valeurs finales pour validation
    final_type = updates.get(
        "type_evenement",
        existing["type_evenement"]
    )

    final_raw = updates.get(
        "donnees_brutes",
        existing["donnees_brutes"]
    )

    # Si MariaDB nous renvoie une chaîne JSON
    if isinstance(final_raw, str):
        try:
            final_raw = json.loads(final_raw)
        except json.JSONDecodeError:
            pass

    final_level = updates.get(
        "niveau_wazuh",
        existing["niveau_wazuh"]
    )

    validate_evenement({
        "type_evenement": final_type,
        "donnees_brutes": final_raw,
        "niveau_wazuh": final_level
    })

    # Vérification source si modifiée
    if "id_source" in updates:

        source_exists = db.execute(
            text("""
                SELECT id_source
                FROM source_donnees
                WHERE id_source = :id_source
                LIMIT 1
            """),
            {
                "id_source": uuid_bytes(
                    updates["id_source"]
                )
            }
        ).first()

        if not source_exists:
            raise HTTPException(
                status_code=404,
                detail="Source de données not found"
            )

    # Vérification agent si modifié
    if "id_agent" in updates and updates["id_agent"]:

        agent_exists = db.execute(
            text("""
                SELECT id_agent
                FROM agent
                WHERE id_agent = :id_agent
                LIMIT 1
            """),
            {
                "id_agent": uuid_bytes(
                    updates["id_agent"]
                )
            }
        ).first()

        if not agent_exists:
            raise HTTPException(
                status_code=404,
                detail="Agent not found"
            )

    # Vérification actif si modifié
    if "id_actif" in updates and updates["id_actif"]:

        actif_exists = db.execute(
            text("""
                SELECT id_actif
                FROM actif
                WHERE id_actif = :id_actif
                LIMIT 1
            """),
            {
                "id_actif": uuid_bytes(
                    updates["id_actif"]
                )
            }
        ).first()

        if not actif_exists:
            raise HTTPException(
                status_code=404,
                detail="Actif not found"
            )

    # Conversion des paramètres
    set_parts = []
    params = {
        "id": item_id.bytes
    }

    uuid_fields = {
        "id_agent",
        "id_actif",
        "id_source"
    }

    json_fields = {
        "donnees_brutes",
        "donnees_normalisees"
    }

    allowed_fields = {
        "id_agent",
        "id_actif",
        "id_source",
        "identifiant_externe",
        "timestamp_evenement",
        "type_evenement",
        "categorie",
        "titre",
        "description",
        "severite",
        "niveau_wazuh",
        "rule_id_externe",
        "decoder",
        "utilisateur",
        "hostname",
        "localisation",
        "donnees_brutes",
        "donnees_normalisees"
    }

    for key, value in updates.items():

        if key not in allowed_fields:
            continue

        if key in uuid_fields:

            params[key] = (
                uuid_bytes(value)
                if value is not None
                else None
            )

        elif key in json_fields:

            params[key] = (
                json.dumps(
                    value,
                    ensure_ascii=False
                )
                if value is not None
                else None
            )

        else:
            params[key] = value

        set_parts.append(
            f"{key} = :{key}"
        )

    if not set_parts:
        return {
            "id_evenement": str(item_id),
            "message": "No changes"
        }

    db.execute(
        text(f"""
            UPDATE evenement
            SET {", ".join(set_parts)}
            WHERE id_evenement = :id
        """),
        params
    )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement updated successfully"
    }


@router.delete("/{item_id}")
def delete_evenement(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("EVENT_READ"))
):
    result = db.execute(
        text("""
            DELETE FROM evenement
            WHERE id_evenement = :id
        """),
        {
            "id": item_id.bytes
        }
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="evenement not found"
        )

    db.commit()

    return {
        "id_evenement": str(item_id),
        "message": "Evenement deleted successfully"
    }