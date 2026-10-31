from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models.evenement import Evenement
from app.models.source_donnees import SourceDonnees
from app.models.agent import Agent
from app.models.actif import Actif


def wazuh_level_to_severity(level):
    """
    Conversion du niveau Wazuh 0-15
    vers l'enum de severite de la table EVENEMENT.
    """
    if level is None:
        return None

    try:
        level = int(level)
    except (ValueError, TypeError):
        return None

    if level <= 3:
        return "LOW"
    elif level <= 7:
        return "MEDIUM"
    elif level <= 11:
        return "HIGH"
    else:
        return "CRITICAL"


def parse_datetime(value):
    """
    Accepte les formats de date présents dans Wazuh.
    """
    if not value:
        return datetime.now(timezone.utc)

    try:
        # Exemple :
        # 2026-09-06T00:09:59.733+0000
        if value.endswith("+0000"):
            return datetime.strptime(
                value,
                "%Y-%m-%dT%H:%M:%S.%f%z"
            )

        # Exemple :
        # 2026-09-06T00:11:05.4194469Z
        value = value.replace("Z", "+00:00")

        return datetime.fromisoformat(value)

    except (ValueError, TypeError):
        return datetime.now(timezone.utc)


def ingest_wazuh_event(db: Session, raw: dict):

    # ============================================================
    # 1. Récupération du vrai contenu Wazuh
    # ============================================================

    source = raw.get("_source") or {}

    if not source:
        raise ValueError(
            "Alerte Wazuh invalide : champ '_source' absent"
        )

    # ============================================================
    # 2. Source de données Wazuh
    # ============================================================

    src = (
        db.query(SourceDonnees)
        .filter(
            SourceDonnees.nom.ilike("Wazuh%")
        )
        .first()
    )

    if not src:
        raise ValueError(
            "Source_Donnees Wazuh not found"
        )

    # ============================================================
    # 3. Agent Wazuh
    # ============================================================

    agent_data = source.get("agent") or {}

    wazuh_agent_id = agent_data.get("id")
    wazuh_agent_name = agent_data.get("name")
    wazuh_agent_ip = agent_data.get("ip")

    if not wazuh_agent_id:
        raise ValueError(
            "Alerte Wazuh invalide : agent.id absent"
        )

    # Recherche par identifiant externe Wazuh
    agent = (
        db.query(Agent)
        .filter(
            Agent.identifiant_externe
            == str(wazuh_agent_id)
        )
        .first()
    )

    if not agent:
        raise ValueError(
            f"Agent Wazuh introuvable : "
            f"{wazuh_agent_id}"
        )

    # ============================================================
    # 4. Actif correspondant à l'agent
    # ============================================================

    actif = None

    if wazuh_agent_ip:
        actif = (
            db.query(Actif)
            .filter(
                Actif.adresse_ip
                == wazuh_agent_ip
            )
            .first()
        )

    # ============================================================
    # 5. Rule Wazuh
    # ============================================================

    rule = source.get("rule") or {}

    rule_id = rule.get("id")
    rule_level = rule.get("level")
    rule_description = rule.get("description")

    groups = rule.get("groups") or []

    categorie = None

    if isinstance(groups, list) and groups:
        categorie = groups[0]

    # ============================================================
    # 6. Decoder
    # ============================================================

    decoder_data = source.get("decoder") or {}

    decoder_name = None

    if isinstance(decoder_data, dict):
        decoder_name = decoder_data.get("name")

    # ============================================================
    # 7. Data Windows Defender
    # ============================================================

    data = source.get("data") or {}

    win = {}

    if isinstance(data, dict):
        win = data.get("win") or {}

    eventdata = {}

    if isinstance(win, dict):
        eventdata = win.get("eventdata") or {}

    system = {}

    if isinstance(win, dict):
        system = win.get("system") or {}

    # ============================================================
    # 8. Informations Windows Defender
    # ============================================================

    detection_user = eventdata.get("detection User")

    threat_name = eventdata.get("threat Name")

    category_name = eventdata.get("category Name")

    severity_name = eventdata.get("severity Name")

    action_name = eventdata.get("action Name")

    file_path = eventdata.get("path")

    windows_event_id = system.get("eventID")

    windows_computer = system.get("computer")

    provider_name = system.get("providerName")

    system_time = system.get("systemTime")

    # ============================================================
    # 9. Timestamp
    # ============================================================

    timestamp = source.get("timestamp")

    if not timestamp:
        timestamp = system_time

    event_datetime = parse_datetime(timestamp)

    # ============================================================
    # 10. Sévérité
    # ============================================================

    severity = wazuh_level_to_severity(rule_level)

    # Pour ton alerte :
    #
    # Wazuh level = 12
    # => CRITICAL

    # ============================================================
    # 11. Identifiant externe
    # ============================================================

    external_id = (
        source.get("id")
        or raw.get("_id")
    )

    # ============================================================
    # 12. Données normalisées
    # ============================================================

    normalized_data = {
        "source": "Wazuh",

        "agent": {
            "id": wazuh_agent_id,
            "name": wazuh_agent_name,
            "ip": wazuh_agent_ip
        },

        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule_description,
            "groups": groups
        },

        "decoder": decoder_name,

        "windows": {
            "event_id": windows_event_id,
            "computer": windows_computer,
            "provider": provider_name,

            "threat_name": threat_name,
            "category": category_name,
            "severity": severity_name,

            "detection_user": detection_user,

            "action": action_name,

            "path": file_path
        }
    }

    # ============================================================
    # 13. Création EVENEMENT
    # ============================================================

    event = Evenement(

        # Agent Wazuh
        id_agent=agent.id_agent,

        # Actif correspondant
        id_actif=(
            actif.id_actif
            if actif
            else None
        ),

        # Source Wazuh
        id_source=src.id_source,

        # ID de l'alerte Wazuh
        identifiant_externe=external_id,

        # Timestamp événement
        timestamp_evenement=event_datetime,

        # Timestamp réception
        timestamp_reception=datetime.now(timezone.utc),

        # Type
        type_evenement="WAZUH_ALERT",

        # Catégorie
        categorie=categorie,

        # Titre
        titre=rule_description,

        # Description
        description=rule_description,

        # Sévérité convertie
        severite=severity,

        # Niveau Wazuh
        niveau_wazuh=rule_level,

        # Rule ID
        rule_id_externe=(
            str(rule_id)
            if rule_id is not None
            else None
        ),

        # Decoder
        decoder=decoder_name,

        # Utilisateur Windows
        utilisateur=detection_user,

        # Machine Windows
        hostname=windows_computer,

        # Localisation
        localisation=None,

        # JSON original complet
        donnees_brutes=raw,

        # JSON normalisé
        donnees_normalisees=normalized_data
    )

    # ============================================================
    # 14. Enregistrement
    # ============================================================

    db.add(event)

    db.commit()

    db.refresh(event)

    # ============================================================
    # 15. Réponse
    # ============================================================

    return {
        "id_evenement": str(event.id_evenement),

        "status": "stored",

        "agent": {
            "id": str(agent.id_agent),
            "external_id": agent.identifiant_externe,
            "name": wazuh_agent_name,
            "ip": wazuh_agent_ip
        },

        "actif": (
            str(actif.id_actif)
            if actif
            else None
        ),

        "source": "Wazuh",

        "rule": {
            "id": str(rule_id)
            if rule_id is not None
            else None,

            "level": rule_level,

            "description": rule_description
        },

        "severity": severity,

        "decoder": decoder_name,

        "windows": {
            "event_id": windows_event_id,
            "computer": windows_computer,
            "provider": provider_name,
            "threat_name": threat_name,
            "category": category_name,
            "severity": severity_name,
            "detection_user": detection_user,
            "action": action_name
        }
    }