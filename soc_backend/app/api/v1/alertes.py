from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission
from app.services.alert_generation_service import (
    generate_alert_from_event,
)
from app.services.mitre_service import (
    get_alert_mitre,
)


router = APIRouter(
    prefix="/alerte",
    tags=["alerte"],
)


# ============================================================
# SCHEMAS
# ============================================================

class AlerteCreate(BaseModel):
    id_regle_detection: uuid.UUID | None = None
    id_regle_correlation: uuid.UUID | None = None
    id_utilisateur_createur: uuid.UUID | None = None
    source_alerte: str
    identifiant_externe: str | None = None
    identifiant_thehive: str | None = None
    titre: str
    description: str | None = None
    severite: str
    statut: str


class AlerteUpdate(BaseModel):
    id_regle_detection: uuid.UUID | None = None
    id_regle_correlation: uuid.UUID | None = None
    id_utilisateur_createur: uuid.UUID | None = None
    source_alerte: str | None = None
    identifiant_externe: str | None = None
    identifiant_thehive: str | None = None
    titre: str | None = None
    description: str | None = None
    severite: str | None = None
    statut: str | None = None
    date_cloture: datetime | None = None


# ============================================================
# VALIDATION
# ============================================================

def validate_alert(data):
    source = data.get("source_alerte")

    if source not in {
        "DETECTION",
        "CORRELATION",
        "MANUAL",
    }:
        raise HTTPException(
            status_code=422,
            detail=(
                "source_alerte must be DETECTION, "
                "CORRELATION or MANUAL"
            ),
        )

    detection = data.get("id_regle_detection")
    correlation = data.get("id_regle_correlation")
    creator = data.get("id_utilisateur_createur")

    if source == "DETECTION":

        if not detection:
            raise HTTPException(
                status_code=422,
                detail=(
                    "DETECTION requires "
                    "id_regle_detection"
                ),
            )

        if correlation:
            raise HTTPException(
                status_code=422,
                detail=(
                    "DETECTION cannot have "
                    "id_regle_correlation"
                ),
            )

    elif source == "CORRELATION":

        if not correlation:
            raise HTTPException(
                status_code=422,
                detail=(
                    "CORRELATION requires "
                    "id_regle_correlation"
                ),
            )

        if detection:
            raise HTTPException(
                status_code=422,
                detail=(
                    "CORRELATION cannot have "
                    "id_regle_detection"
                ),
            )

    elif source == "MANUAL":

        if detection or correlation:
            raise HTTPException(
                status_code=422,
                detail=(
                    "MANUAL cannot have "
                    "detection/correlation rule"
                ),
            )

        if not creator:
            raise HTTPException(
                status_code=422,
                detail=(
                    "MANUAL requires "
                    "id_utilisateur_createur"
                ),
            )


# ============================================================
# SERIALIZATION
# ============================================================

def serialize_uuid(value):
    if (
        isinstance(value, (bytes, bytearray))
        and len(value) == 16
    ):
        return str(
            uuid.UUID(
                bytes=bytes(value)
            )
        )

    return value


def serialize_row(row):
    if row is None:
        return None

    result = {}

    for key, value in row.items():

        if (
            isinstance(value, (bytes, bytearray))
            and len(value) == 16
        ):
            value = str(
                uuid.UUID(
                    bytes=bytes(value)
                )
            )

        elif isinstance(value, datetime):
            value = value.isoformat()

        result[key] = value

    return result


# ============================================================
# LIST ALERTS
# ============================================================

@router.get("")
def list_alerts(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_READ")
    ),
):
    offset = (page - 1) * page_size

    rows = db.execute(
        text(
            """
            SELECT *
            FROM alerte
            ORDER BY date_creation DESC
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
            "SELECT COUNT(*) FROM alerte"
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


# ============================================================
# GET ALERT DETAIL
# ============================================================

@router.get("/{item_id}")
def get_alert(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_READ")
    ),
):
    # ========================================================
    # 1. ALERTE
    # ========================================================

    row = db.execute(
        text(
            """
            SELECT *
            FROM alerte
            WHERE id_alerte = :id
            """
        ),
        {
            "id": item_id.bytes,
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="alerte not found",
        )

    alert = serialize_row(row)

    # ========================================================
    # 2. EVENEMENT
    # ========================================================

    evenement = None

    # --------------------------------------------------------
    # 2.1 Recherche via alerte_evenement
    # --------------------------------------------------------

    evenement_row = db.execute(
        text(
            """
            SELECT e.*
            FROM alerte_evenement ae
            INNER JOIN evenement e
                ON e.id_evenement = ae.id_evenement
            WHERE ae.id_alerte = :id_alerte
            ORDER BY
                CASE
                    WHEN ae.role_evenement = 'SOURCE'
                    THEN 0
                    ELSE 1
                END,
                e.timestamp_evenement DESC
            LIMIT 1
            """
        ),
        {
            "id_alerte": item_id.bytes,
        },
    ).mappings().first()

    if evenement_row:
        evenement = serialize_row(
            evenement_row
        )

    # --------------------------------------------------------
    # 2.2 Fallback pour les anciennes alertes
    # --------------------------------------------------------

    if evenement is None:

        identifiant_externe = (
            alert.get("identifiant_externe")
        )

        if identifiant_externe:

            evenement_row = db.execute(
                text(
                    """
                    SELECT *
                    FROM evenement
                    WHERE identifiant_externe = :identifiant_externe
                    ORDER BY timestamp_evenement DESC
                    LIMIT 1
                    """
                ),
                {
                    "identifiant_externe":
                        identifiant_externe,
                },
            ).mappings().first()

            if evenement_row:
                evenement = serialize_row(
                    evenement_row
                )

    # ========================================================
    # 2.3 CLASSIFICATION / MITRE
    # ========================================================

    classification = {
        "event_type": None,
        "mitre": {
            "techniques": [],
            "tactics": [],
        },
    }

    # --------------------------------------------------------
    # Event type
    #
    # Le type d'événement continue d'être récupéré
    # depuis donnees_normalisees.
    # --------------------------------------------------------

    if evenement:

        normalized_event = evenement.get(
            "donnees_normalisees"
        )

        if isinstance(
            normalized_event,
            dict,
        ):

            event_type = normalized_event.get(
                "event_type"
            )

            if event_type:

                classification[
                    "event_type"
                ] = str(
                    event_type
                ).strip()

    # --------------------------------------------------------
    # MITRE
    #
    # IMPORTANT :
    # Le MITRE affiché par l'API provient maintenant
    # exclusivement des relations SQL.
    #
    # alerte
    #   -> alerte_evenement
    #   -> evenement_mitre
    #   -> technique_mitre
    #   -> technique_tactique
    #   -> tactique_mitre
    #
    # Aucun fallback vers :
    #   - donnees_normalisees.mitre
    #   - Wazuh rule MITRE
    #   - OWASP
    # --------------------------------------------------------

    classification["mitre"] = get_alert_mitre(
        db,
        item_id,
    )

    # ========================================================
    # 3. EVALUATION RISQUE
    # ========================================================

    risque_row = None

    # --------------------------------------------------------
    # 3.1 Priorité : risque lié à l'événement
    # --------------------------------------------------------

    if evenement and evenement.get("id_evenement"):

        risque_row = db.execute(
            text(
                """
                SELECT *
                FROM evaluation_risque
                WHERE id_evenement = :id_evenement
                ORDER BY date_calcul DESC
                LIMIT 1
                """
            ),
            {
                "id_evenement": uuid.UUID(
                    str(evenement["id_evenement"])
                ).bytes,
            },
        ).mappings().first()

    # --------------------------------------------------------
    # 3.2 Fallback : risque lié directement à l'alerte
    # --------------------------------------------------------

    if risque_row is None:

        risque_row = db.execute(
            text(
                """
                SELECT *
                FROM evaluation_risque
                WHERE id_alerte = :id_alerte
                ORDER BY date_calcul DESC
                LIMIT 1
                """
            ),
            {
                "id_alerte": item_id.bytes,
            },
        ).mappings().first()

    evaluation_risque = (
        serialize_row(risque_row)
        if risque_row
        else None
    )

    # ========================================================
    # 4. INCIDENT
    # ========================================================

    incident_row = db.execute(
        text(
            """
            SELECT *
            FROM incident
            WHERE id_alerte = :id_alerte
            ORDER BY date_creation DESC
            LIMIT 1
            """
        ),
        {
            "id_alerte": item_id.bytes,
        },
    ).mappings().first()

    incident = (
        serialize_row(incident_row)
        if incident_row
        else None
    )

    # ========================================================
    # 5. THEHIVE
    # ========================================================

    thehive = None

    identifiant_thehive = (
        alert.get("identifiant_thehive")
    )

    if identifiant_thehive:
        thehive = {
            "identifiant": identifiant_thehive
        }

    # ========================================================
    # 6. IOC
    # ========================================================

    iocs = []

    if evenement and evenement.get("id_evenement"):

        ioc_rows = db.execute(
            text(
                """
                SELECT
                    i.id_ioc,
                    i.type_ioc,
                    i.valeur,
                    i.is_ioc,
                    i.date_premiere_observation,
                    i.date_derniere_observation,
                    ei.role_ioc,
                    ei.contexte
                FROM evenement_ioc ei
                INNER JOIN ioc i
                    ON i.id_ioc = ei.id_ioc
                WHERE ei.id_evenement = :id_evenement
                ORDER BY i.date_derniere_observation DESC
                """
            ),
            {
                "id_evenement": uuid.UUID(
                    str(evenement["id_evenement"])
                ).bytes,
            },
        ).mappings().all()

        iocs = [
            serialize_row(row)
            for row in ioc_rows
        ]

    # ========================================================
    # 6.1 THREAT INTELLIGENCE
    # ========================================================

    threat_intelligence = {
        "virustotal": [],
        "abuseipdb": [],
    }

    for ioc in iocs:

        ioc_id = ioc.get("id_ioc")

        if not ioc_id:
            continue

        try:
            ioc_uuid = uuid.UUID(
                str(ioc_id)
            )
        except (ValueError, TypeError):
            continue

        # ----------------------------------------------------
        # VirusTotal
        # ----------------------------------------------------

        vt_row = db.execute(
            text(
                """
                SELECT
                    id_ti_vt,
                    id_ioc,
                    malicious_count,
                    suspicious_count,
                    harmless_count,
                    undetected_count,
                    total_engines,
                    reputation,
                    last_analysis_date,
                    permalink
                FROM threat_intelligence_vt
                WHERE id_ioc = :id_ioc
                LIMIT 1
                """
            ),
            {
                "id_ioc": ioc_uuid.bytes,
            },
        ).mappings().first()

        if vt_row:

            vt_data = serialize_row(
                vt_row
            )

            vt_data["type_ioc"] = (
                ioc.get("type_ioc")
            )

            vt_data["valeur"] = (
                ioc.get("valeur")
            )

            threat_intelligence[
                "virustotal"
            ].append(vt_data)

        # ----------------------------------------------------
        # AbuseIPDB
        # ----------------------------------------------------

        abuse_row = db.execute(
            text(
                """
                SELECT
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
                    checked_at
                FROM threat_intelligence_abuseipdb
                WHERE id_ioc = :id_ioc
                LIMIT 1
                """
            ),
            {
                "id_ioc": ioc_uuid.bytes,
            },
        ).mappings().first()

        if abuse_row:

            abuse_data = serialize_row(
                abuse_row
            )

            abuse_data["type_ioc"] = (
                ioc.get("type_ioc")
            )

            abuse_data["valeur"] = (
                ioc.get("valeur")
            )

            threat_intelligence[
                "abuseipdb"
            ].append(abuse_data)

    # ========================================================
    # 7. REPONSE COMPLETE
    # ========================================================

    return {
        **alert,

        "evenement": evenement,

        "classification": classification,

        "iocs": iocs,

        "threat_intelligence":
            threat_intelligence,

        "evaluation_risque":
            evaluation_risque,

        "incident":
            incident,

        "thehive":
            thehive,
    }


# ============================================================
# CREATE ALERT
# ============================================================

@router.post(
    "",
    status_code=201,
)
def create_alert(
    body: AlerteCreate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_CREATE")
    ),
):
    data = body.model_dump()

    # Pour une alerte manuelle,
    # le créateur est l'utilisateur connecté.
    if data["source_alerte"] == "MANUAL":
        data["id_utilisateur_createur"] = (
            current_user.id_utilisateur
        )

    validate_alert(data)

    now = datetime.now(timezone.utc)
    alert_id = uuid.uuid4()

    db.execute(
        text(
            """
            INSERT INTO alerte (
                id_alerte,
                id_regle_detection,
                id_regle_correlation,
                id_utilisateur_createur,
                source_alerte,
                identifiant_externe,
                identifiant_thehive,
                titre,
                description,
                severite,
                statut,
                date_creation,
                date_mise_a_jour,
                date_cloture
            )
            VALUES (
                :id_alerte,
                :id_regle_detection,
                :id_regle_correlation,
                :id_utilisateur_createur,
                :source_alerte,
                :identifiant_externe,
                :identifiant_thehive,
                :titre,
                :description,
                :severite,
                :statut,
                :date_creation,
                :date_mise_a_jour,
                :date_cloture
            )
            """
        ),
        {
            "id_alerte": alert_id.bytes,

            "id_regle_detection": (
                data["id_regle_detection"].bytes
                if data["id_regle_detection"]
                else None
            ),

            "id_regle_correlation": (
                data["id_regle_correlation"].bytes
                if data["id_regle_correlation"]
                else None
            ),

            "id_utilisateur_createur": (
                data[
                    "id_utilisateur_createur"
                ].bytes
                if data[
                    "id_utilisateur_createur"
                ]
                else None
            ),

            "source_alerte":
                data["source_alerte"],

            "identifiant_externe":
                data["identifiant_externe"],

            "identifiant_thehive":
                data["identifiant_thehive"],

            "titre":
                data["titre"],

            "description":
                data["description"],

            "severite":
                data["severite"],

            "statut":
                data["statut"],

            "date_creation":
                now,

            "date_mise_a_jour":
                now,

            "date_cloture":
                None,
        },
    )

    db.commit()

    return {
        "id_alerte": str(alert_id),
        "message": "Alert created successfully",
    }


# ============================================================
# UPDATE ALERT
# ============================================================

@router.put("/{item_id}")
def update_alert(
    item_id: uuid.UUID,
    body: AlerteUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_UPDATE")
    ),
):
    alert_id = item_id.bytes

    row = db.execute(
        text(
            """
            SELECT *
            FROM alerte
            WHERE id_alerte = :id
            """
        ),
        {
            "id": alert_id,
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="alerte not found",
        )

    current = dict(row)

    updates = body.model_dump(
        exclude_unset=True
    )

    final_data = {
        key: current.get(key)
        for key in current
    }

    final_data.update(updates)

    # Les UUID lus depuis MariaDB
    # sont convertis en UUID Python.
    for key in (
        "id_regle_detection",
        "id_regle_correlation",
        "id_utilisateur_createur",
    ):
        value = final_data.get(key)

        if isinstance(
            value,
            (bytes, bytearray),
        ):
            final_data[key] = uuid.UUID(
                bytes=bytes(value)
            )

    validate_alert(final_data)

    allowed = {
        "id_regle_detection",
        "id_regle_correlation",
        "id_utilisateur_createur",
        "source_alerte",
        "identifiant_externe",
        "identifiant_thehive",
        "titre",
        "description",
        "severite",
        "statut",
        "date_cloture",
    }

    set_parts = []

    params = {
        "id": alert_id
    }

    for key, value in updates.items():

        if key not in allowed:
            continue

        set_parts.append(
            f"{key} = :{key}"
        )

        if isinstance(
            value,
            uuid.UUID,
        ):
            value = value.bytes

        params[key] = value

    if not set_parts:
        return {
            "id_alerte": str(item_id),
            "message": "No changes",
        }

    set_parts.append(
        "date_mise_a_jour = :date_mise_a_jour"
    )

    params[
        "date_mise_a_jour"
    ] = datetime.now(timezone.utc)

    db.execute(
        text(
            f"""
            UPDATE alerte
            SET {", ".join(set_parts)}
            WHERE id_alerte = :id
            """
        ),
        params,
    )

    db.commit()

    return {
        "id_alerte": str(item_id),
        "message": "Alert updated successfully",
    }


# ============================================================
# DELETE ALERT
# ============================================================

@router.delete("/{item_id}")
def delete_alert(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_DELETE")
    ),
):
    result = db.execute(
        text(
            """
            DELETE FROM alerte
            WHERE id_alerte = :id
            """
        ),
        {
            "id": item_id.bytes,
        },
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="alerte not found",
        )

    db.commit()

    return {
        "id_alerte": str(item_id),
        "message": "Alert deleted successfully",
    }


# ============================================================
# CREATE ALERT FROM EVENT
# ============================================================

@router.post(
    "/from-evenement/{event_id}",
    status_code=201,
)
def create_alert_from_event(
    event_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_CREATE")
    ),
):
    return generate_alert_from_event(
        db=db,
        event_id=event_id,
    )