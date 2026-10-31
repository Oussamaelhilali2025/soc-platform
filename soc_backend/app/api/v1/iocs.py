import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/ioc",
    tags=["IOC"],
)


# ============================================================
# Utilitaires
# ============================================================

def serialize_row(row):
    """
    Convertit une ligne SQLAlchemy RowMapping en dictionnaire
    JSON-compatible.
    """
    if row is None:
        return None

    data = dict(row)

    for key, value in data.items():
        if isinstance(value, uuid.UUID):
            data[key] = str(value)

        # UUID stocké en BINARY(16) dans MariaDB/MySQL
        elif isinstance(value, bytes) and len(value) == 16:
            try:
                data[key] = str(uuid.UUID(bytes=value))
            except ValueError:
                data[key] = value.hex()

        # Autres données binaires éventuelles
        elif isinstance(value, bytes):
            data[key] = value.hex()

    return data


def parse_json(value):
    """
    Convertit une valeur JSON provenant de MariaDB/MySQL
    en dictionnaire Python.
    """
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    return {}


def serialize_security_context(rows):
    """
    Transforme les lignes issues du JOIN IOC -> événement ->
    alerte -> risque -> incident en structure lisible par le frontend.
    """
    alerts = []

    for row in rows:
        data = serialize_row(row)

        normalized = parse_json(data.get("donnees_normalisees"))

        # ----------------------------------------------------
        # MITRE
        # ----------------------------------------------------
        mitre = normalized.get("mitre")

        if mitre is None:
            mitre = {}

        # Certains workflows peuvent stocker MITRE sous forme
        # de liste ou directement sous un autre format.
        if not isinstance(mitre, (dict, list)):
            mitre = {}

        # ----------------------------------------------------
        # Événement
        # ----------------------------------------------------
        event = None

        if data.get("id_evenement"):
            event = {
                "id_evenement": data.get("id_evenement"),
                "wazuh_event_id": data.get("wazuh_event_id"),
                "timestamp": data.get("timestamp_evenement"),
                "titre": data.get("evenement_titre"),
                "severite": data.get("evenement_severite"),
                "rule_id": data.get("rule_id_externe"),
                "niveau_wazuh": data.get("niveau_wazuh"),
                "type_evenement": data.get("type_evenement"),
                "hostname": data.get("hostname"),
            }

        # ----------------------------------------------------
        # Risque
        # ----------------------------------------------------
        risk = None

        if data.get("id_evaluation"):
            risk = {
                "id_evaluation": data.get("id_evaluation"),
                "score": data.get("score_risque"),
                "niveau": data.get("niveau_risque"),
                "action": data.get("action_recommandee"),
                "raison": data.get("raison"),
                "force_case": data.get("force_case"),
                "date_calcul": data.get("date_calcul"),
            }

        # ----------------------------------------------------
        # Incident / TheHive
        # ----------------------------------------------------
        incident = None

        if data.get("id_incident"):
            incident = {
                "id_incident": data.get("id_incident"),
                "titre": data.get("incident_titre"),
                "statut": data.get("incident_statut"),
                "priorite": data.get("incident_priorite"),
                "severite": data.get("incident_severite"),
                "identifiant_thehive": data.get(
                    "incident_identifiant_thehive"
                ),
                "date_creation": data.get("incident_date_creation"),
                "date_mise_a_jour": data.get(
                    "incident_date_mise_a_jour"
                ),
                "date_cloture": data.get("incident_date_cloture"),
            }

        # ----------------------------------------------------
        # Alerte
        # ----------------------------------------------------
        alert = {
            "id_alerte": data.get("id_alerte"),
            "identifiant_externe": data.get("alert_external_id"),
            "identifiant_thehive": data.get(
                "alert_identifiant_thehive"
            ),
            "titre": data.get("alerte_titre"),
            "description": data.get("alerte_description"),
            "severite": data.get("alerte_severite"),
            "statut": data.get("alerte_statut"),
            "date_creation": data.get("alert_date_creation"),
            "date_mise_a_jour": data.get("alert_date_mise_a_jour"),
            "date_cloture": data.get("alert_date_cloture"),
            "event": event,
            "risk": risk,
            "mitre": mitre,
            "incident": incident,
        }

        # Une relation IOC -> événement sans alerte reste
        # également exploitable.
        if data.get("id_alerte"):
            alerts.append(alert)

    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
    }


# ============================================================
# Liste des IOC
# ============================================================

@router.get("")
def get_iocs(
    page: int = 1,
    page_size: int = 200,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    """
    Retourne la liste paginée des IOC.
    """
    offset = (page - 1) * page_size

    total_row = db.execute(
        text(
            """
            SELECT COUNT(*) AS total
            FROM ioc
            """
        )
    ).mappings().first()

    total = int(total_row["total"]) if total_row else 0

    rows = db.execute(
        text(
            """
            SELECT
                id_ioc,
                type_ioc,
                valeur,
                is_ioc,
                date_premiere_observation,
                date_derniere_observation
            FROM ioc
            ORDER BY date_derniere_observation DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {
            "limit": page_size,
            "offset": offset,
        },
    ).mappings().all()

    items = [
        serialize_row(row)
        for row in rows
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": (
            (total + page_size - 1) // page_size
            if page_size > 0
            else 0
        ),
    }


# ============================================================
# Détail d'un IOC
# ============================================================

@router.get("/{item_id}")
def get_ioc(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("IOC_READ")),
):
    """
    Retourne le détail complet d'un IOC :

    - informations générales
    - VirusTotal
    - AbuseIPDB
    - alertes associées
    - événements Wazuh
    - évaluation de risque
    - MITRE
    - incident / TheHive
    """

    # ========================================================
    # 1. IOC principal
    # ========================================================

    row = db.execute(
        text(
            """
            SELECT
                id_ioc,
                type_ioc,
                valeur,
                is_ioc,
                date_premiere_observation,
                date_derniere_observation
            FROM ioc
            WHERE id_ioc = :id
            """
        ),
        {
            "id": item_id.bytes,
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="ioc not found",
        )

    ioc_data = serialize_row(row)

    # ========================================================
    # 2. VirusTotal
    # ========================================================

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
            WHERE id_ioc = :id
            ORDER BY last_analysis_date DESC
            LIMIT 1
            """
        ),
        {
            "id": item_id.bytes,
        },
    ).mappings().first()

    # ========================================================
    # 3. AbuseIPDB
    # ========================================================

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
            WHERE id_ioc = :id
            ORDER BY checked_at DESC
            LIMIT 1
            """
        ),
        {
            "id": item_id.bytes,
        },
    ).mappings().first()

    # ========================================================
    # 4. Contexte de sécurité
    #
    # IOC
    #   ↓ evenement_ioc
    # Evenement
    #   ↓ alerte_evenement
    # Alerte
    #   ↓ evaluation_risque
    # Risque
    #   ↓ incident
    # Incident / TheHive
    # ========================================================

    security_rows = db.execute(
        text(
            """
            SELECT
                /* ==============================
                   ÉVÉNEMENT
                   ============================== */

                e.id_evenement,
                e.identifiant_externe AS wazuh_event_id,
                e.timestamp_evenement,
                e.titre AS evenement_titre,
                e.severite AS evenement_severite,
                e.rule_id_externe,
                e.niveau_wazuh,
                e.type_evenement,
                e.hostname,
                e.donnees_normalisees,

                /* ==============================
                   ALERTE
                   ============================== */

                a.id_alerte,
                a.identifiant_externe AS alert_external_id,
                a.identifiant_thehive AS alert_identifiant_thehive,
                a.titre AS alerte_titre,
                a.description AS alerte_description,
                a.severite AS alerte_severite,
                a.statut AS alerte_statut,
                a.date_creation AS alert_date_creation,
                a.date_mise_a_jour AS alert_date_mise_a_jour,
                a.date_cloture AS alert_date_cloture,

                /* ==============================
                   DERNIÈRE ÉVALUATION DE RISQUE
                   ============================== */

                er.id_evaluation,
                er.score_risque,
                er.niveau_risque,
                er.action_recommandee,
                er.raison,
                er.force_case,
                er.date_calcul,

                /* ==============================
                   INCIDENT
                   ============================== */

                i.id_incident,
                i.titre AS incident_titre,
                i.statut AS incident_statut,
                i.priorite AS incident_priorite,
                i.severite AS incident_severite,
                i.identifiant_thehive
                    AS incident_identifiant_thehive,
                i.date_creation
                    AS incident_date_creation,
                i.date_mise_a_jour
                    AS incident_date_mise_a_jour,
                i.date_cloture
                    AS incident_date_cloture

            FROM evenement_ioc ei

            INNER JOIN evenement e
                ON e.id_evenement = ei.id_evenement

            LEFT JOIN alerte_evenement ae
                ON ae.id_evenement = e.id_evenement

            LEFT JOIN alerte a
                ON a.id_alerte = ae.id_alerte

            /* ------------------------------------
               On récupère uniquement la dernière
               évaluation de risque pour l'événement.
               ------------------------------------ */

            LEFT JOIN (
                SELECT er1.*
                FROM evaluation_risque er1

                INNER JOIN (
                    SELECT
                        id_evenement,
                        MAX(date_calcul) AS max_date
                    FROM evaluation_risque
                    WHERE id_evenement IS NOT NULL
                    GROUP BY id_evenement
                ) latest
                    ON latest.id_evenement = er1.id_evenement
                    AND latest.max_date = er1.date_calcul

            ) er
                ON er.id_evenement = e.id_evenement

            LEFT JOIN incident i
                ON i.id_alerte = a.id_alerte

            WHERE ei.id_ioc = :id_ioc

            ORDER BY
                e.timestamp_evenement DESC,
                er.date_calcul DESC
            """
        ),
        {
            "id_ioc": item_id.bytes,
        },
    ).mappings().all()

    security_context = serialize_security_context(
        security_rows
    )

    # ========================================================
    # 5. Ajouter les enrichissements
    # ========================================================

    ioc_data["enrichment"] = {
        "virustotal": (
            serialize_row(vt_row)
            if vt_row
            else None
        ),
        "abuseipdb": (
            serialize_row(abuse_row)
            if abuse_row
            else None
        ),
    }

    # ========================================================
    # 6. Ajouter le contexte de sécurité
    # ========================================================

    ioc_data["security_context"] = security_context

    # ========================================================
    # 7. Réponse finale
    # ========================================================

    return ioc_data