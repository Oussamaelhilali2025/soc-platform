from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission
from app.services.thehive_service import TheHiveService, TheHiveError


router = APIRouter(
    prefix="/incident",
    tags=["incident"],
)


class IncidentCreate(BaseModel):
    id_alerte: uuid.UUID | None = None
    id_actif: uuid.UUID | None = None
    id_utilisateur_createur: uuid.UUID | None = None
    id_utilisateur_assigne: uuid.UUID | None = None
    identifiant_thehive: str | None = None
    titre: str
    description: str | None = None
    severite: str
    priorite: str
    statut: str


class IncidentUpdate(BaseModel):
    id_alerte: uuid.UUID | None = None
    id_actif: uuid.UUID | None = None
    id_utilisateur_createur: uuid.UUID | None = None
    id_utilisateur_assigne: uuid.UUID | None = None
    identifiant_thehive: str | None = None
    titre: str | None = None
    description: str | None = None
    severite: str | None = None
    priorite: str | None = None
    statut: str | None = None
    date_cloture: datetime | None = None


def serialize_row(row):
    result = {}

    for key, value in row.items():
        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            value = str(uuid.UUID(bytes=bytes(value)))

        elif isinstance(value, datetime):
            value = value.isoformat()

        result[key] = value

    return result


def convert_uuid_values(data):
    for key in (
        "id_incident",
        "id_alerte",
        "id_actif",
        "id_utilisateur_createur",
        "id_utilisateur_assigne",
    ):
        value = data.get(key)

        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            data[key] = uuid.UUID(bytes=bytes(value))

    return data


@router.post("", status_code=201)
def create_incident(
    body: IncidentCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("INCIDENT_CREATE")),
):
    data = body.model_dump()

    # Le créateur est toujours l'utilisateur authentifié.
    data["id_utilisateur_createur"] = current_user.id_utilisateur

    incident_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    db.execute(
        text(
            """
            INSERT INTO incident (
                id_incident,
                id_alerte,
                id_actif,
                id_utilisateur_createur,
                id_utilisateur_assigne,
                identifiant_thehive,
                titre,
                description,
                severite,
                priorite,
                statut,
                date_creation,
                date_mise_a_jour,
                date_cloture
            )
            VALUES (
                :id_incident,
                :id_alerte,
                :id_actif,
                :id_utilisateur_createur,
                :id_utilisateur_assigne,
                :identifiant_thehive,
                :titre,
                :description,
                :severite,
                :priorite,
                :statut,
                :date_creation,
                :date_mise_a_jour,
                :date_cloture
            )
            """
        ),
        {
            "id_incident": incident_id.bytes,
            "id_alerte": (
                data["id_alerte"].bytes
                if data["id_alerte"]
                else None
            ),
            "id_actif": (
                data["id_actif"].bytes
                if data["id_actif"]
                else None
            ),
            "id_utilisateur_createur": (
                current_user.id_utilisateur.bytes
            ),
            "id_utilisateur_assigne": (
                data["id_utilisateur_assigne"].bytes
                if data["id_utilisateur_assigne"]
                else None
            ),
            "identifiant_thehive": data["identifiant_thehive"],
            "titre": data["titre"],
            "description": data["description"],
            "severite": data["severite"],
            "priorite": data["priorite"],
            "statut": data["statut"],
            "date_creation": now,
            "date_mise_a_jour": now,
            "date_cloture": None,
        },
    )

    db.commit()

    return {
        "id_incident": str(incident_id),
        "message": "Incident created successfully",
    }


@router.post(
    "/from-alerte/{alert_id}",
    status_code=201,
)
def create_incident_from_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_CREATE")
    ),
):
    alert = db.execute(
        text(
            """
            SELECT
                a.*,
                rd.identifiant_externe AS rule_external_id
            FROM alerte a
            LEFT JOIN regle_detection rd
                ON rd.id_regle_detection =
                   a.id_regle_detection
            WHERE a.id_alerte = :id
            """
        ),
        {"id": alert_id.bytes},
    ).mappings().first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alerte introuvable",
        )

    existing = db.execute(
        text(
            """
            SELECT id_incident
            FROM incident
            WHERE id_alerte = :id_alerte
            """
        ),
        {"id_alerte": alert_id.bytes},
    ).mappings().first()

    if existing:
        existing_id = uuid.UUID(
            bytes=existing["id_incident"]
        )

        raise HTTPException(
            status_code=409,
            detail={
                "message": (
                    "Un incident existe déjà "
                    "pour cette alerte."
                ),
                "id_incident": str(existing_id),
            },
        )

    actif = db.execute(
        text(
            """
            SELECT e.id_actif
            FROM alerte_evenement ae
            INNER JOIN evenement e
                ON e.id_evenement = ae.id_evenement
            WHERE ae.id_alerte = :id_alerte
              AND e.id_actif IS NOT NULL
            LIMIT 1
            """
        ),
        {"id_alerte": alert_id.bytes},
    ).mappings().first()

    id_actif = actif["id_actif"] if actif else None

    severity_map = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    thehive_severity = severity_map.get(
        str(alert["severite"]).upper(),
        2,
    )

    source_ref = (
        alert["identifiant_externe"]
        or str(alert_id)
    )

    thehive = TheHiveService()

    # ---------------------------------------------------------
    # Création de l'alerte TheHive
    # ---------------------------------------------------------
    try:
        thehive_alert = thehive.create_alert(
            title=alert["titre"],
            description=(
                alert["description"]
                or "Alerte générée par SOC Platform."
            ),
            source="SOC Platform",
            source_ref=source_ref,
            severity=thehive_severity,
            tlp=2,
            pap=2,
            alert_type="soc-platform",
            tags=[
                "soc-platform",
                str(alert["source_alerte"]).lower(),
                str(alert["severite"]).lower(),
            ],
        )

    except TheHiveError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )

    thehive_alert_id = (
        thehive_alert.get("_id")
        or thehive_alert.get("id")
    )

    if not thehive_alert_id:
        raise HTTPException(
            status_code=502,
            detail=(
                "TheHive a créé l'alerte mais "
                "n'a pas retourné son identifiant."
            ),
        )

    # ---------------------------------------------------------
    # Création du Case TheHive
    # ---------------------------------------------------------
    try:
        thehive_case = (
            thehive.create_case_from_alert(
                thehive_alert_id,
                title=alert["titre"],
                description=(
                    alert["description"]
                    or "Incident créé automatiquement."
                ),
                severity=thehive_severity,
                tlp=2,
                pap=2,
            )
        )

    except TheHiveError as exc:
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        )

    thehive_case_id = (
        thehive_case.get("_id")
        or thehive_case.get("id")
    )

    if not thehive_case_id:
        raise HTTPException(
            status_code=502,
            detail=(
                "TheHive a créé le Case mais "
                "n'a pas retourné son identifiant."
            ),
        )

    # ---------------------------------------------------------
    # Création de l'incident dans SOC Platform
    # ---------------------------------------------------------
    incident_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    db.execute(
        text(
            """
            INSERT INTO incident (
                id_incident,
                id_alerte,
                id_actif,
                id_utilisateur_createur,
                id_utilisateur_assigne,
                identifiant_thehive,
                titre,
                description,
                severite,
                priorite,
                statut,
                date_creation,
                date_mise_a_jour,
                date_cloture
            )
            VALUES (
                :id_incident,
                :id_alerte,
                :id_actif,
                :id_utilisateur_createur,
                :id_utilisateur_assigne,
                :identifiant_thehive,
                :titre,
                :description,
                :severite,
                :priorite,
                :statut,
                :date_creation,
                :date_mise_a_jour,
                :date_cloture
            )
            """
        ),
        {
            "id_incident": incident_id.bytes,
            "id_alerte": alert_id.bytes,
            "id_actif": id_actif,
            "id_utilisateur_createur": (
                current_user.id_utilisateur.bytes
            ),
            "id_utilisateur_assigne": None,
            "identifiant_thehive": thehive_case_id,
            "titre": alert["titre"],
            "description": alert["description"],
            "severite": alert["severite"],
            "priorite": (
                "CRITICAL"
                if thehive_severity == 4
                else "HIGH"
                if thehive_severity == 3
                else "MEDIUM"
                if thehive_severity == 2
                else "LOW"
            ),
            "statut": "NEW",
            "date_creation": now,
            "date_mise_a_jour": now,
            "date_cloture": None,
        },
    )

    db.commit()

    return {
        "status": "created",
        "id_incident": str(incident_id),
        "id_alerte": str(alert_id),
        "thehive_alert_id": thehive_alert_id,
        "thehive_case_id": thehive_case_id,
        "message": (
            "Incident et Case TheHive "
            "créés avec succès."
        ),
    }


@router.get("")
def list_incidents(
    page: int = 1,
    page_size: int = 1000,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_READ")
    ),
):
    if page < 1:
        raise HTTPException(
            422,
            "page must be >= 1",
        )

    if page_size < 1 or page_size > 3000:
        raise HTTPException(
            422,
            "page_size must be between 1 and 200",
        )

    offset = (page - 1) * page_size

    rows = db.execute(
        text(
            """
            SELECT *
            FROM incident
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
            "SELECT COUNT(*) FROM incident"
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
@router.get("/users")
def list_active_users(
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_UPDATE")
    ),
):
    rows = db.execute(
        text(
            """
            SELECT
                id_utilisateur,
                nom_utilisateur,
                nom,
                prenom
            FROM utilisateur
            WHERE statut = 'ACTIVE'
            ORDER BY nom, prenom
            """
        )
    ).mappings().all()

    users = []

    for row in rows:
        user_id = row["id_utilisateur"]

        if isinstance(user_id, (bytes, bytearray)) and len(user_id) == 16:
            user_id = str(
                uuid.UUID(bytes=bytes(user_id))
            )

        users.append(
            {
                "id_utilisateur": user_id,
                "nom_utilisateur": row["nom_utilisateur"],
                "nom": row["nom"],
                "prenom": row["prenom"],
            }
        )

    return users

@router.get("/{item_id}")
def get_incident(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_READ")
    ),
):
    row = db.execute(
        text(
            """
            SELECT
    i.*,
    uc.nom AS createur_nom,
    uc.prenom AS createur_prenom,
    ua.nom AS assigne_nom,
    ua.prenom AS assigne_prenom
FROM incident i
LEFT JOIN utilisateur uc
    ON uc.id_utilisateur = i.id_utilisateur_createur
LEFT JOIN utilisateur ua
    ON ua.id_utilisateur = i.id_utilisateur_assigne
WHERE i.id_incident = :id
            """
        ),
        {
            "id": item_id.bytes,
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    return serialize_row(row)


@router.put("/{item_id}")
def update_incident(
    item_id: uuid.UUID,
    body: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_UPDATE")
    ),
):
    incident_id = item_id.bytes

    # ---------------------------------------------------------
    # Vérifier que l'incident existe
    # ---------------------------------------------------------
    row = db.execute(
        text(
            """
            SELECT *
            FROM incident
            WHERE id_incident = :id
            """
        ),
        {
            "id": incident_id,
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    # ---------------------------------------------------------
    # Récupérer les champs envoyés
    # ---------------------------------------------------------
    updates = body.model_dump(
        exclude_unset=True
    )

    allowed = {
        "id_alerte",
        "id_actif",
        "id_utilisateur_createur",
        "id_utilisateur_assigne",
        "identifiant_thehive",
        "titre",
        "description",
        "severite",
        "priorite",
        "statut",
        "date_cloture",
    }

    # ---------------------------------------------------------
    # Gestion automatique de la date de clôture
    # ---------------------------------------------------------
    if updates.get("statut") in {
        "RESOLVED",
        "CLOSED",
    }:
        updates["date_cloture"] = (
            datetime.now(timezone.utc)
        )

    # ---------------------------------------------------------
    # Préparation de la requête UPDATE
    # ---------------------------------------------------------
    set_parts = []
    params = {
        "id": incident_id,
    }

    for key, value in updates.items():

        if key not in allowed:
            continue

        if isinstance(value, uuid.UUID):
            value = value.bytes

        set_parts.append(
            f"{key} = :{key}"
        )

        params[key] = value

    if not set_parts:
        return {
            "id_incident": str(item_id),
            "message": "No changes",
        }

    # Toujours mettre à jour la date de modification.
    set_parts.append(
        "date_mise_a_jour = :date_mise_a_jour"
    )

    params["date_mise_a_jour"] = (
        datetime.now(timezone.utc)
    )

    # ---------------------------------------------------------
    # Mise à jour de l'incident
    # ---------------------------------------------------------
        # ---------------------------------------------------------
    # Mise à jour de l'incident
    # ---------------------------------------------------------
    db.execute(
        text(
            f"""
            UPDATE incident
            SET {", ".join(set_parts)}
            WHERE id_incident = :id
            """
        ),
        params,
    )

    # ---------------------------------------------------------
    # Synchronisation Incident -> Alerte
    # ---------------------------------------------------------
    if updates.get("statut") in {
        "RESOLVED",
        "CLOSED",
    }:
        incident_alert = db.execute(
            text(
                """
                SELECT id_alerte
                FROM incident
                WHERE id_incident = :id
                """
            ),
            {
                "id": incident_id,
            },
        ).mappings().first()

        if (
            incident_alert
            and incident_alert["id_alerte"]
        ):
            db.execute(
                text(
                    """
                    UPDATE alerte
                    SET
                        statut = :statut,
                        date_cloture = :date_cloture,
                        date_mise_a_jour = :date_mise_a_jour
                    WHERE id_alerte = :id_alerte
                    """
                ),
                {
                    "id_alerte": incident_alert["id_alerte"],
                    "statut": updates["statut"],
                    "date_cloture": updates["date_cloture"],
                    "date_mise_a_jour": params["date_mise_a_jour"],
                },
            )

    db.commit()
    # ---------------------------------------------------------
    # Synchronisation avec TheHive
    # ---------------------------------------------------------
    if (
        "statut" in updates
        and updates["statut"]
    ):
        incident_case = db.execute(
            text(
                """
                SELECT identifiant_thehive
                FROM incident
                WHERE id_incident = :id
                """
            ),
            {
                "id": incident_id,
            },
        ).mappings().first()

        if (
            incident_case
            and incident_case[
                "identifiant_thehive"
            ]
        ):
            try:
                thehive = TheHiveService()

                thehive.update_case_status(
                    incident_case[
                        "identifiant_thehive"
                    ],
                    updates["statut"],
                )

            except TheHiveError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Incident mis à jour, mais "
                        f"synchronisation TheHive échouée : {exc}"
                    ),
                )

    return {
        "id_incident": str(item_id),
        "message": "Incident updated successfully",
    }


@router.delete("/{item_id}")
def delete_incident(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_CLOSE")
    ),
):
    result = db.execute(
        text(
            """
            DELETE FROM incident
            WHERE id_incident = :id
            """
        ),
        {
            "id": item_id.bytes,
        },
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="incident not found",
        )

    db.commit()

    return {
        "id_incident": str(item_id),
        "message": "Incident deleted successfully",
    }
