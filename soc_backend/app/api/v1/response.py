"""
API des actions de réponse (EDR-like) liées aux incidents.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission
from app.services.glpi import GLPIService
from app.services.wazuh_response_service import (
    WazuhResponseError,
    WazuhResponseService,
)


router = APIRouter(
    prefix="/response",
    tags=["response"],
)


# ============================================================================
# ACTIONS SUPPORTÉES
# ============================================================================

SUPPORTED_ACTIONS = {
    "ISOLATE_HOST": {
        "label": "Isoler l'hôte",
        "phase": "immediate",
        "needs_agent": True,
        "wazuh_command": "route-null",
    },
    "BLOCK_IP": {
        "label": "Bloquer une IP",
        "phase": "immediate",
        "needs_agent": True,
        "wazuh_command": "route-null",
    },
    "BLOCK_HASH": {
        "label": "Bloquer un hash (IOC)",
        "phase": "immediate",
        "needs_agent": True,
        "wazuh_command": "block-hash",
    },
    "KILL_PROCESS": {
        "label": "Tuer un processus",
        "phase": "immediate",
        "needs_agent": True,
        "wazuh_command": "kill-process",
    },
    "COLLECT_LOGS": {
        "label": "Collecter les logs agent",
        "phase": "short_term",
        "needs_agent": True,
        "wazuh_command": "collect-logs",
    },
    "CREATE_GLPI_TICKET": {
        "label": "Créer un ticket GLPI",
        "phase": "short_term",
        "needs_agent": False,
        "wazuh_command": None,
    },
    "ADD_NOTE": {
        "label": "Ajouter une note d'investigation",
        "phase": "short_term",
        "needs_agent": False,
        "wazuh_command": None,
    },
}


# ============================================================================
# SCHÉMAS
# ============================================================================

class ActionCreate(BaseModel):
    id_incident: uuid.UUID
    id_alerte: uuid.UUID | None = None
    type_action: str
    cible: str | None = None
    parametres: dict[str, Any] | None = None

    origine_action: str = Field(
        default="MANUAL",
        pattern="^(MANUAL|AUTOMATED)$",
    )


class ActionOut(BaseModel):
    id_action: str
    id_incident: str | None
    id_alerte: str | None
    id_utilisateur: str | None
    type_action: str
    cible: str | None
    statut: str
    origine_action: str
    date_execution: str | None
    parametres: dict | None = None
    resultat: dict | None = None


# ============================================================================
# HELPERS
# ============================================================================

def serialize_row(row) -> dict:
    """
    Convertit une ligne SQLAlchemy Row en dictionnaire JSON-compatible.
    """

    result = {}

    for key, value in dict(row).items():

        if isinstance(value, (bytes, bytearray)) and len(value) == 16:
            value = str(uuid.UUID(bytes=bytes(value)))

        elif isinstance(value, datetime):
            value = value.isoformat()

        elif key in ("parametres", "resultat") and isinstance(value, str):
            try:
                value = json.loads(value)
            except Exception:
                pass

        result[key] = value

    return result


def parse_json_field(value) -> dict | None:
    """
    Parse un champ JSON provenant de MariaDB.
    """

    if value is None:
        return None

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)

            if isinstance(parsed, dict):
                return parsed

            return {
                "raw": parsed,
            }

        except Exception:
            return {
                "raw": value,
            }

    return {
        "raw": str(value),
    }


# ============================================================================
# CATALOGUE DES ACTIONS
# ============================================================================

@router.get("/actions/catalog")
def list_action_catalog(
    current_user=Depends(require_permission("INCIDENT_READ")),
):
    """
    Liste les actions de réponse disponibles pour le portail SOC.
    """

    return {
        "items": [
            {
                "type_action": key,
                **meta,
            }
            for key, meta in SUPPORTED_ACTIONS.items()
        ]
    }


# ============================================================================
# HISTORIQUE DES ACTIONS PAR INCIDENT
# ============================================================================

@router.get("/incidents/{incident_id}/actions")
def list_incident_actions(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("INCIDENT_READ")),
):
    rows = db.execute(
        text(
            """
            SELECT
                ar.*,
                u.nom_utilisateur,
                u.nom,
                u.prenom
            FROM action_reponse ar
            LEFT JOIN utilisateur u
                ON u.id_utilisateur = ar.id_utilisateur
            WHERE ar.id_incident = :id_incident
            ORDER BY ar.date_execution DESC
            """
        ),
        {
            "id_incident": incident_id.bytes,
        },
    ).mappings().all()

    return {
        "items": [
            serialize_row(row)
            for row in rows
        ],
        "total": len(rows),
    }


# ============================================================================
# DONNÉES COLLECT_LOGS / TRIAGE
# ============================================================================

@router.get("/incidents/{incident_id}/collected-logs")
async def get_collected_logs(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("INCIDENT_READ")),
):
    """
    Récupère les dernières données de triage COLLECT_LOGS
    pour l'agent Wazuh associé à l'incident.
    """

    # ------------------------------------------------------------------------
    # 1. Récupérer incident + actif + agent
    # ------------------------------------------------------------------------

    incident = db.execute(
        text(
            """
            SELECT
                i.id_incident,
                i.id_actif,
                i.id_alerte,

                a.identifiant_externe AS agent_id,
                a.nom AS agent_nom,
                a.adresse_ip AS agent_ip

            FROM incident i

            LEFT JOIN actif ac
                ON ac.id_actif = i.id_actif

            LEFT JOIN agent a
                ON a.id_agent = ac.id_agent

            WHERE i.id_incident = :id_incident
            """
        ),
        {
            "id_incident": incident_id.bytes,
        },
    ).mappings().first()

    if not incident:
        raise HTTPException(
            status_code=404,
            detail="Incident introuvable",
        )

    # ------------------------------------------------------------------------
    # 2. Récupérer l'agent
    # ------------------------------------------------------------------------

    agent_id = incident.get("agent_id")
    agent_nom = incident.get("agent_nom")
    agent_ip = incident.get("agent_ip")

    # ------------------------------------------------------------------------
    # 3. Fallback : dernière action COLLECT_LOGS
    # ------------------------------------------------------------------------

    if not agent_id:

        action_row = db.execute(
            text(
                """
                SELECT
                    parametres
                FROM action_reponse
                WHERE
                    id_incident = :id_incident
                    AND type_action = 'COLLECT_LOGS'
                ORDER BY date_execution DESC
                LIMIT 1
                """
            ),
            {
                "id_incident": incident_id.bytes,
            },
        ).mappings().first()

        if action_row:

            params = parse_json_field(
                action_row.get("parametres")
            )

            if isinstance(params, dict):

                agent_id = (
                    params.get("agent_id")
                    or params.get("agent")
                )

                agent_nom = (
                    agent_nom
                    or params.get("agent_name")
                    or params.get("agent_nom")
                )

                agent_ip = (
                    agent_ip
                    or params.get("agent_ip")
                    or params.get("ip")
                )

    # ------------------------------------------------------------------------
    # 4. Aucun agent
    # ------------------------------------------------------------------------

    if not agent_id:

        return {
            "found": False,
            "message": (
                "Aucun agent Wazuh n'est associé "
                "à cet incident. "
                "Pour COLLECT_LOGS, fournissez agent_id "
                "dans les paramètres de l'action."
            ),
            "incident_id": str(incident_id),
            "agent": {
                "id": None,
                "name": agent_nom,
                "ip": agent_ip,
            },
            "data": None,
        }

    agent_id = str(agent_id)

    # ------------------------------------------------------------------------
    # 5. Interroger Wazuh
    # ------------------------------------------------------------------------

    wazuh = WazuhResponseService()

    try:

        triage = await wazuh.get_latest_triage_data(
            agent_id
        )

    except WazuhResponseError as exc:

        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    # ------------------------------------------------------------------------
    # 6. Aucune donnée
    # ------------------------------------------------------------------------

    if triage is None:

        return {
            "found": False,
            "message": (
                "Aucune donnée COLLECT_LOGS disponible "
                "pour cet agent."
            ),
            "incident_id": str(incident_id),
            "agent": {
                "id": agent_id,
                "name": agent_nom,
                "ip": agent_ip,
            },
            "data": None,
        }

    # ------------------------------------------------------------------------
    # 7. Données trouvées
    # ------------------------------------------------------------------------

    return {
        "found": True,
        "message": "Données COLLECT_LOGS récupérées",
        "incident_id": str(incident_id),
        "agent": {
            "id": agent_id,
            "name": (
                agent_nom
                or triage.get("computer")
            ),
            "ip": agent_ip,
        },
        "data": triage,
    }


# ============================================================================
# LANCER UNE ACTION
# ============================================================================

@router.post("/actions", status_code=201)
async def create_action(
    body: ActionCreate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("INCIDENT_UPDATE")),
):
    """
    Exécute une action de réponse et enregistre son résultat
    dans action_reponse.
    """

    # ------------------------------------------------------------------------
    # 1. Normalisation du type d'action
    # ------------------------------------------------------------------------

    type_action = body.type_action.strip().upper()

    if type_action not in SUPPORTED_ACTIONS:

        raise HTTPException(
            status_code=422,
            detail=(
                f"type_action inconnu: {type_action}. "
                f"Supportés: {', '.join(SUPPORTED_ACTIONS)}"
            ),
        )

    # ------------------------------------------------------------------------
    # 2. Vérifier que l'incident existe
    # ------------------------------------------------------------------------

    incident = db.execute(
        text(
            """
            SELECT
                id_incident,
                id_alerte,
                id_actif,
                statut,
                titre,
                description
            FROM incident
            WHERE id_incident = :id
            """
        ),
        {
            "id": body.id_incident.bytes,
        },
    ).mappings().first()

    if not incident:

        raise HTTPException(
            status_code=404,
            detail="Incident introuvable",
        )

    # ------------------------------------------------------------------------
    # 3. Préparation
    # ------------------------------------------------------------------------

    meta = SUPPORTED_ACTIONS[type_action]

    params = body.parametres or {}

    cible = (
        body.cible
        or params.get("cible")
        or ""
    ).strip() or None

    action_id = uuid.uuid4()

    now = datetime.now(timezone.utc)

    statut = "PENDING"

    resultat: dict[str, Any] = {}

    # ------------------------------------------------------------------------
    # 4. Exécution
    # ------------------------------------------------------------------------

    try:

        # ====================================================================
        # ADD_NOTE
        # ====================================================================

        if type_action == "ADD_NOTE":

            note = (
                params.get("note")
                or params.get("message")
                or ""
            )

            if not str(note).strip():

                raise HTTPException(
                    status_code=422,
                    detail="parametres.note requis",
                )

            statut = "SUCCEEDED"

            resultat = {
                "note": str(note).strip(),
                "message": "Note enregistrée",
            }

        # ====================================================================
        # ACTIONS WAZUH
        # ====================================================================

        elif type_action in (
            "ISOLATE_HOST",
            "BLOCK_IP",
            "BLOCK_HASH",
            "KILL_PROCESS",
            "COLLECT_LOGS",
        ):

            # ----------------------------------------------------------------
            # Récupérer les informations de l'agent
            # ----------------------------------------------------------------

            agent_id = (
                params.get("agent_id")
                or params.get("agent")
            )

            agent_name = params.get("agent_name")
            agent_ip = params.get("agent_ip")

            # ----------------------------------------------------------------
            # Fallback : actif -> agent
            # ----------------------------------------------------------------

            if not agent_id and incident["id_actif"]:

                agent_row = db.execute(
                    text(
                        """
                        SELECT
                            a.identifiant_externe,
                            a.nom,
                            a.adresse_ip
                        FROM actif ac
                        LEFT JOIN agent a
                            ON a.id_agent = ac.id_agent
                        WHERE ac.id_actif = :id_actif
                        """
                    ),
                    {
                        "id_actif": incident["id_actif"],
                    },
                ).mappings().first()

                if (
                    agent_row
                    and agent_row["identifiant_externe"]
                ):

                    agent_id = str(
                        agent_row["identifiant_externe"]
                    )

                    agent_name = (
                        agent_name
                        or agent_row["nom"]
                    )

                    agent_ip = (
                        agent_ip
                        or agent_row["adresse_ip"]
                    )

                    if not cible:

                        cible = (
                            agent_row["adresse_ip"]
                            or agent_row["nom"]
                        )

            # ----------------------------------------------------------------
            # Vérifier agent
            # ----------------------------------------------------------------

            if meta["needs_agent"] and not agent_id:

                statut = "FAILED"

                resultat = {
                    "message": (
                        "Aucun agent Wazuh associé "
                        "à l'incident. "
                        "Passez agent_id dans parametres."
                    ),
                }

            else:

                command = meta.get("wazuh_command")

                arguments: list[str] = []

                alert_payload: dict[str, Any] | None = None

                # ============================================================
                # BLOCK_HASH
                # ============================================================

                if type_action == "BLOCK_HASH":

                    hash_value = (
                        body.cible
                        or params.get("hash")
                        or params.get("sha256")
                        or params.get("sha256_hash")
                    )

                    if not hash_value:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "cible ou parametres.hash requis "
                                "pour BLOCK_HASH"
                            ),
                        )

                    hash_value = str(
                        hash_value
                    ).strip().lower()

                    if len(hash_value) != 64:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "Le hash doit être "
                                "un SHA256 valide"
                            ),
                        )

                    if any(
                        char not in "0123456789abcdef"
                        for char in hash_value
                    ):

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "Le hash SHA256 doit être "
                                "hexadécimal"
                            ),
                        )

                    arguments = [
                        hash_value
                    ]

                    cible = hash_value

                    # --------------------------------------------------------
                    # Chemin du fichier
                    # --------------------------------------------------------

                    file_path = (
                        params.get("file_path")
                        or params.get("path")
                        or params.get("filename")
                    )

                    if not file_path:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "parametres.file_path requis "
                                "pour BLOCK_HASH"
                            ),
                        )

                    file_path = str(
                        file_path
                    ).strip()

                    if not file_path:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "parametres.file_path ne peut pas "
                                "être vide pour BLOCK_HASH"
                            ),
                        )

                    alert_payload = {
                        "data": {
                            "path": file_path,
                        },
                        "syscheck": {
                            "path": file_path,
                        },
                    }

                # ============================================================
                # BLOCK_IP
                # ============================================================

                elif type_action == "BLOCK_IP":

                    if not cible:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "cible (IP) requise "
                                "pour BLOCK_IP"
                            ),
                        )

                    arguments = [
                        cible
                    ]

                # ============================================================
                # ISOLATE_HOST
                # ============================================================

                elif type_action == "ISOLATE_HOST":

                    if not cible:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "cible requise "
                                "pour ISOLATE_HOST"
                            ),
                        )

                    arguments = [
                        cible
                    ]

                # ============================================================
                # KILL_PROCESS
                # ============================================================

                elif type_action == "KILL_PROCESS":

                    pid = (
                        params.get("pid")
                        or params.get("process")
                    )

                    if pid is None:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "parametres.pid requis "
                                "pour KILL_PROCESS"
                            ),
                        )

                    pid_str = str(
                        pid
                    ).strip()

                    if not pid_str.isdigit():

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "parametres.pid doit être "
                                "un PID numérique"
                            ),
                        )

                    pid_int = int(
                        pid_str
                    )

                    if pid_int <= 0:

                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "parametres.pid doit être "
                                "supérieur à 0"
                            ),
                        )

                    arguments = [
                        str(pid_int)
                    ]

                # ============================================================
                # COLLECT_LOGS
                # ============================================================

                elif type_action == "COLLECT_LOGS":

                    arguments = []

                    if agent_id:
                        params["agent_id"] = str(
                            agent_id
                        )

                    if agent_name:
                        params["agent_name"] = agent_name

                    if agent_ip:
                        params["agent_ip"] = agent_ip

                # ----------------------------------------------------------------
                # Exécution Wazuh
                # ----------------------------------------------------------------

                if command:

                    try:

                        wazuh = WazuhResponseService()

                        wazuh_result = (
                            wazuh.run_active_response(
                                command=command,
                                agent_id=(
                                    str(agent_id)
                                    if agent_id
                                    else None
                                ),
                                arguments=arguments,
                                alert=alert_payload,
                            )
                        )

                        statut = "SUCCEEDED"

                        resultat = {
                            "message": (
                                "Active Response soumise"
                            ),
                            "wazuh": wazuh_result,
                        }

                    except WazuhResponseError as exc:

                        statut = "FAILED"

                        resultat = {
                            "message": str(exc),
                        }

                else:

                    statut = "SUCCEEDED"

                    resultat = {
                        "message": (
                            f"Action {type_action} enregistrée "
                            "(connecteur non branché, "
                            "dry logique)"
                        ),
                        "agent_id": agent_id,
                        "cible": cible,
                    }

        # ====================================================================
        # CREATE_GLPI_TICKET
        # ====================================================================

        elif type_action == "CREATE_GLPI_TICKET":

            title = (
                params.get("title")
                or incident["titre"]
                or "Incident SOC"
            )

            description = (
                params.get("description")
                or incident["description"]
                or (
                    "Ticket créé automatiquement depuis "
                    f"l'incident SOC {body.id_incident}"
                )
            )

            try:

                urgency = int(
                    params.get("urgency", 3)
                )

            except (TypeError, ValueError):

                raise HTTPException(
                    status_code=422,
                    detail=(
                        "parametres.urgency doit être "
                        "un entier"
                    ),
                )

            if urgency < 1 or urgency > 5:

                raise HTTPException(
                    status_code=422,
                    detail=(
                        "parametres.urgency doit être "
                        "comprise entre 1 et 5"
                    ),
                )

            try:

                glpi = GLPIService()

                glpi_result = await glpi.create_ticket(
                    name=str(title),
                    content=str(description),
                    urgency=urgency,
                )

                statut = "SUCCEEDED"

                resultat = {
                    "message": "Ticket GLPI créé avec succès",
                    "glpi": glpi_result,
                }

            except Exception as exc:

                statut = "FAILED"

                resultat = {
                    "message": (
                        "Échec de création du ticket GLPI"
                    ),
                    "error": str(exc),
                }

        # ====================================================================
        # ACTION INCONNUE / NON IMPLÉMENTÉE
        # ====================================================================

        else:

            statut = "FAILED"

            resultat = {
                "message": "Action non implémentée",
            }

    # ------------------------------------------------------------------------
    # Gestion HTTPException
    # ------------------------------------------------------------------------

    except HTTPException:
        raise

    # ------------------------------------------------------------------------
    # Gestion des autres erreurs
    # ------------------------------------------------------------------------

    except Exception as exc:

        statut = "FAILED"

        resultat = {
            "message": str(exc),
        }

    # =========================================================================
    # PERSISTANCE DANS action_reponse
    # =========================================================================

    id_alerte = (
        body.id_alerte.bytes
        if body.id_alerte
        else incident["id_alerte"]
    )

    db.execute(
        text(
            """
            INSERT INTO action_reponse (
                id_action,
                id_utilisateur,
                id_alerte,
                id_incident,
                origine_action,
                type_action,
                cible,
                parametres,
                resultat,
                statut,
                date_execution
            )
            VALUES (
                :id_action,
                :id_utilisateur,
                :id_alerte,
                :id_incident,
                :origine_action,
                :type_action,
                :cible,
                :parametres,
                :resultat,
                :statut,
                :date_execution
            )
            """
        ),
        {
            "id_action": action_id.bytes,
            "id_utilisateur": current_user.id_utilisateur.bytes,
            "id_alerte": id_alerte,
            "id_incident": body.id_incident.bytes,
            "origine_action": body.origine_action,
            "type_action": type_action,
            "cible": cible,
            "parametres": json.dumps(
                params,
                ensure_ascii=False,
            ),
            "resultat": json.dumps(
                resultat,
                ensure_ascii=False,
            ),
            "statut": statut,
            "date_execution": now,
        },
    )

    db.commit()

    # =========================================================================
    # RÉPONSE API
    # =========================================================================

    return {
        "id_action": str(action_id),
        "type_action": type_action,
        "statut": statut,
        "cible": cible,
        "resultat": resultat,
        "message": "Action de réponse enregistrée",
    }


# ============================================================================
# CONSULTER UNE ACTION
# ============================================================================

@router.get("/actions/{action_id}")
def get_action(
    action_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission("INCIDENT_READ")),
):
    row = db.execute(
        text(
            """
            SELECT
                ar.*,
                u.nom_utilisateur,
                u.nom,
                u.prenom
            FROM action_reponse ar
            LEFT JOIN utilisateur u
                ON u.id_utilisateur = ar.id_utilisateur
            WHERE ar.id_action = :id
            """
        ),
        {
            "id": action_id.bytes,
        },
    ).mappings().first()

    if not row:

        raise HTTPException(
            status_code=404,
            detail="Action introuvable",
        )

    return serialize_row(row)