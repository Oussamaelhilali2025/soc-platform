from datetime import datetime, timezone
import uuid

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session


def generate_alert_from_event(
    db: Session,
    event_id: uuid.UUID,
):
    """
    Transforme un événement Wazuh en alerte DETECTION
    et crée automatiquement la relation ALERTE ↔ EVENEMENT.
    """

    # ============================================================
    # 1. RÉCUPÉRER L'ÉVÉNEMENT
    # ============================================================

    event = db.execute(
        text(
            """
            SELECT *
            FROM evenement
            WHERE id_evenement = :id_evenement
            """
        ),
        {
            "id_evenement": event_id.bytes
        },
    ).mappings().first()

    if not event:
        raise HTTPException(
            status_code=404,
            detail="Événement introuvable",
        )

    # ============================================================
    # 2. VÉRIFIER QU'IL S'AGIT BIEN D'UN ÉVÉNEMENT WAZUH
    # ============================================================

    if event["type_evenement"] != "WAZUH_ALERT":
        raise HTTPException(
            status_code=422,
            detail=(
                "L'événement n'est pas un événement Wazuh : "
                f"{event['type_evenement']}"
            ),
        )

    # ============================================================
    # 3. RÉCUPÉRER LE RULE ID WAZUH
    # ============================================================

    rule_id = event["rule_id_externe"]

    if not rule_id:
        raise HTTPException(
            status_code=422,
            detail=(
                "L'événement ne contient pas "
                "de rule_id_externe"
            ),
        )

    # ============================================================
    # 4. CHERCHER LA RÈGLE DE DÉTECTION
    # ============================================================

    detection_rule = db.execute(
        text(
            """
            SELECT *
            FROM regle_detection
            WHERE identifiant_externe = :rule_id
            LIMIT 1
            """
        ),
        {
            "rule_id": str(rule_id)
        },
    ).mappings().first()

    if not detection_rule:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Aucune règle de détection trouvée pour "
                f"le rule_id Wazuh '{rule_id}'. "
                f"Crée d'abord la règle de détection correspondante."
            ),
        )

    # ============================================================
    # 5. VÉRIFIER QUE LA RÈGLE EST ACTIVE
    # ============================================================

    if detection_rule.get("statut") not in (None, "ACTIVE"):
        raise HTTPException(
            status_code=422,
            detail=(
                f"La règle de détection '{rule_id}' "
                f"n'est pas ACTIVE."
            ),
        )

    # ============================================================
    # 6. VÉRIFIER SI UNE ALERTE EXISTE DÉJÀ
    # ============================================================

    existing_alert = db.execute(
        text(
            """
            SELECT id_alerte
            FROM alerte
            WHERE identifiant_externe = :identifiant_externe
            LIMIT 1
            """
        ),
        {
            "identifiant_externe":
                event["identifiant_externe"]
        },
    ).mappings().first()

    if existing_alert:

        existing_id = existing_alert["id_alerte"]

        if isinstance(
            existing_id,
            (bytes, bytearray)
        ):
            existing_id = str(
                uuid.UUID(
                    bytes=bytes(existing_id)
                )
            )

        # --------------------------------------------------------
        # Vérifier si la relation existe déjà
        # --------------------------------------------------------

        relation_exists = db.execute(
            text(
                """
                SELECT 1
                FROM alerte_evenement
                WHERE id_alerte = :id_alerte
                  AND id_evenement = :id_evenement
                LIMIT 1
                """
            ),
            {
                "id_alerte": uuid.UUID(
                    str(existing_id)
                ).bytes,
                "id_evenement": event_id.bytes,
            },
        ).first()

        # --------------------------------------------------------
        # Créer la relation si elle n'existe pas
        # --------------------------------------------------------

        if not relation_exists:
            db.execute(
                text(
                    """
                    INSERT INTO alerte_evenement (
                        id_alerte,
                        id_evenement,
                        role_evenement
                    )
                    VALUES (
                        :id_alerte,
                        :id_evenement,
                        'SOURCE'
                    )
                    """
                ),
                {
                    "id_alerte": uuid.UUID(
                        str(existing_id)
                    ).bytes,
                    "id_evenement": event_id.bytes,
                },
            )

            db.commit()

        return {
            "status": "already_exists",
            "id_alerte": str(existing_id),
            "id_evenement": str(event_id),
            "message": (
                "Une alerte existe déjà pour cet événement."
            ),
        }

    # ============================================================
    # 7. GÉNÉRER L'ID DE L'ALERTE
    # ============================================================

    alert_id = uuid.uuid4()

    now = datetime.now(timezone.utc)

    # ============================================================
    # 8. CONSTRUIRE LE TITRE
    # ============================================================

    titre = event["titre"]

    if not titre:
        titre = (
            f"Alerte Wazuh - règle {rule_id}"
        )

    # ============================================================
    # 9. CONSTRUIRE LA DESCRIPTION
    # ============================================================

    description = event["description"]

    # ============================================================
    # 10. SÉVÉRITÉ
    # ============================================================

    severite = event["severite"]

    if not severite:
        severite = "MEDIUM"

    # ============================================================
    # 11. CRÉER L'ALERTE
    # ============================================================

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
                NULL,
                NULL,
                'DETECTION',
                :identifiant_externe,
                NULL,
                :titre,
                :description,
                :severite,
                'OPEN',
                :date_creation,
                :date_mise_a_jour,
                NULL
            )
            """
        ),
        {
            "id_alerte": alert_id.bytes,

            "id_regle_detection": (
                detection_rule["id_regle_detection"]
            ),

            "identifiant_externe": (
                event["identifiant_externe"]
            ),

            "titre": titre,

            "description": description,

            "severite": severite,

            "date_creation": now,

            "date_mise_a_jour": now,
        },
    )

    # ============================================================
    # 12. CRÉER LA RELATION ALERTE ↔ ÉVÉNEMENT
    # ============================================================

    db.execute(
        text(
            """
            INSERT INTO alerte_evenement (
                id_alerte,
                id_evenement,
                role_evenement
            )
            VALUES (
                :id_alerte,
                :id_evenement,
                'SOURCE'
            )
            """
        ),
        {
            "id_alerte": alert_id.bytes,
            "id_evenement": event_id.bytes,
        },
    )

    # ============================================================
    # 13. COMMIT UNIQUE
    # ============================================================

    db.commit()

    # ============================================================
    # 14. RETOUR
    # ============================================================

    return {
        "status": "created",

        "id_alerte": str(alert_id),

        "id_evenement": str(event_id),

        "source_alerte": "DETECTION",

        "id_regle_detection": str(
            uuid.UUID(
                bytes=bytes(
                    detection_rule[
                        "id_regle_detection"
                    ]
                )
            )
        ),

        "rule_id_wazuh": str(rule_id),

        "titre": titre,

        "severite": severite,

        "statut": "OPEN",

        "message": (
            "Alerte créée à partir de l'événement Wazuh "
            "et associée automatiquement à l'événement source."
        ),
    }