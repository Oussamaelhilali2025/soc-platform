"""
Service d'exécution des actions de réponse via Wazuh Active Response.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.config import settings


class WazuhResponseError(Exception):
    """Erreur lors de l'exécution d'une Active Response Wazuh."""


class WazuhResponseService:
    """
    Wrapper autour de l'API Wazuh Manager pour :

    - déclencher des Active Responses sur un agent Wazuh ;
    - récupérer les données de triage COLLECT_LOGS depuis Wazuh Indexer.
    """

    # ------------------------------------------------------------------
    # Commandes Active Response disponibles directement sur l'agent
    # ------------------------------------------------------------------

    DIRECT_AGENT_COMMANDS = {
        "netsh",
        "firewall-drop",
        "host-deny",
        "route-null",
        "disable-account",
        "restart-wazuh",
        "kill-process",
        "block-hash",
        "collect-logs",
    }

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        self.base_url = settings.WAZUH_API_URL.rstrip("/")

        self.user = settings.WAZUH_API_USER
        self.password = settings.WAZUH_API_PASSWORD

        self.verify_ssl = settings.WAZUH_API_VERIFY_SSL
        self.timeout = settings.WAZUH_API_TIMEOUT

        self.dry_run = settings.WAZUH_RESPONSE_DRY_RUN

    # ==================================================================
    # ACTIVE RESPONSE
    # ==================================================================

    # ------------------------------------------------------------------
    # Normaliser la commande
    # ------------------------------------------------------------------

    def _normalize_command(self, command: str) -> str:
        """
        Wazuh attend le préfixe '!' pour exécuter directement
        une commande Active Response disponible sur l'agent.

        Exemple :

            route-null
                ↓
            !route-null

            kill-process
                ↓
            !kill-process
        """

        command = command.strip()

        if not command:
            raise WazuhResponseError(
                "Commande Active Response vide"
            )

        # Déjà normalisée
        if command.startswith("!"):
            return command

        # Commande locale connue
        if command in self.DIRECT_AGENT_COMMANDS:
            return f"!{command}"

        # Autoriser également les autres commandes déjà configurées
        return command

    # ------------------------------------------------------------------
    # Authentification Wazuh
    # ------------------------------------------------------------------

    def _get_token(
        self,
        client: httpx.Client,
    ) -> str:
        """
        Authentifie le compte Wazuh et récupère le JWT.
        """

        if not self.user:
            raise WazuhResponseError(
                "WAZUH_API_USER n'est pas configuré"
            )

        if not self.password:
            raise WazuhResponseError(
                "WAZUH_API_PASSWORD n'est pas configuré"
            )

        try:
            response = client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(
                    self.user,
                    self.password,
                ),
            )

        except httpx.HTTPError as exc:
            raise WazuhResponseError(
                "Erreur réseau pendant "
                f"l'authentification Wazuh: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise WazuhResponseError(
                "Authentification Wazuh échouée: "
                f"{response.status_code} "
                f"{response.text}"
            )

        try:
            data = response.json()

        except ValueError as exc:
            raise WazuhResponseError(
                "Réponse JSON invalide pendant "
                "l'authentification Wazuh"
            ) from exc

        token = (
            data.get("data", {}).get("token")
            or data.get("token")
        )

        if not token:
            raise WazuhResponseError(
                "Token Wazuh introuvable dans la réponse"
            )

        return token

    # ------------------------------------------------------------------
    # Construire le payload Active Response
    # ------------------------------------------------------------------

    def _build_payload(
        self,
        *,
        command: str,
        normalized_command: str,
        arguments: list[str],
        alert: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Construit le payload envoyé à l'API Wazuh.

        route-null Windows nécessite :

        {
            "alert": {
                "data": {
                    "srcip": "x.x.x.x"
                }
            }
        }

        block-hash Windows nécessite :

        {
            "alert": {
                "data": {
                    "path": "C:\\Users\\...\\fichier.txt"
                },
                "syscheck": {
                    "path": "C:\\Users\\...\\fichier.txt"
                }
            }
        }

        Les autres commandes conservent le payload d'alerte fourni
        par l'appelant.
        """

        payload: dict[str, Any] = {
            "command": normalized_command,
            "arguments": arguments,
            "alert": alert or {},
        }

        command_clean = (
            command.strip()
            .lower()
            .lstrip("!")
        )

        # --------------------------------------------------------------
        # Cas particulier : route-null
        # --------------------------------------------------------------

        if command_clean == "route-null":

            if not arguments:
                raise WazuhResponseError(
                    "Une IP est obligatoire pour route-null"
                )

            source_ip = arguments[0].strip()

            if not source_ip:
                raise WazuhResponseError(
                    "L'IP fournie à route-null est vide"
                )

            # route-null.exe sur Windows lit srcip
            # depuis alert.data.srcip.
            payload["alert"] = {
                "data": {
                    "srcip": source_ip,
                }
            }

        # --------------------------------------------------------------
        # Cas particulier : block-hash
        # --------------------------------------------------------------

        elif command_clean == "block-hash":

            if not arguments:
                raise WazuhResponseError(
                    "Un SHA256 est obligatoire pour block-hash"
                )

            hash_value = arguments[0].strip()

            if not hash_value:
                raise WazuhResponseError(
                    "Le SHA256 fourni à block-hash est vide"
                )

            current_alert = alert or {}

            alert_data = current_alert.get(
                "data",
                {}
            )

            syscheck = current_alert.get(
                "syscheck",
                {}
            )

            if not isinstance(alert_data, dict):
                alert_data = {}

            if not isinstance(syscheck, dict):
                syscheck = {}

            file_path = (
                alert_data.get("path")
                or alert_data.get("file")
                or alert_data.get("filename")
                or syscheck.get("path")
            )

            if not file_path:
                raise WazuhResponseError(
                    "Le chemin du fichier est obligatoire "
                    "pour block-hash"
                )

            file_path = str(file_path).strip()

            if not file_path:
                raise WazuhResponseError(
                    "Le chemin du fichier est vide "
                    "pour block-hash"
                )

            # block-hash.exe récupère :
            # - le SHA256 depuis parameters.extra_args
            # - le chemin depuis alert.data.path
            #   ou alert.syscheck.path.
            payload["alert"] = {
                "data": {
                    "path": file_path,
                },
                "syscheck": {
                    "path": file_path,
                },
            }

        return payload

    # ------------------------------------------------------------------
    # Exécuter Active Response
    # ------------------------------------------------------------------

    def run_active_response(
        self,
        *,
        command: str,
        agent_id: str | None = None,
        arguments: list[str] | None = None,
        alert: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        # --------------------------------------------------------------
        # Vérification agent
        # --------------------------------------------------------------

        if not agent_id:
            raise WazuhResponseError(
                "agent_id est obligatoire pour "
                "une Active Response"
            )

        normalized_command = self._normalize_command(
            command
        )

        normalized_agent_id = str(
            agent_id
        ).strip()

        if not normalized_agent_id:
            raise WazuhResponseError(
                "agent_id invalide"
            )

        # --------------------------------------------------------------
        # Normaliser les arguments
        # --------------------------------------------------------------

        normalized_arguments = [
            str(argument)
            for argument in (arguments or [])
        ]

        # --------------------------------------------------------------
        # Mode DRY RUN
        # --------------------------------------------------------------

        if self.dry_run:

            payload = self._build_payload(
                command=command,
                normalized_command=normalized_command,
                arguments=normalized_arguments,
                alert=alert,
            )

            return {
                "mode": "dry_run",
                "command": command,
                "wazuh_command": normalized_command,
                "agent_id": normalized_agent_id,
                "arguments": normalized_arguments,
                "status": "simulated_success",
                "payload": payload,
                "message": (
                    "Action simulée "
                    "(WAZUH_RESPONSE_DRY_RUN=true). "
                    "Aucun appel réel au Manager."
                ),
            }

        # --------------------------------------------------------------
        # Construire payload réel
        # --------------------------------------------------------------

        payload = self._build_payload(
            command=command,
            normalized_command=normalized_command,
            arguments=normalized_arguments,
            alert=alert,
        )

        # --------------------------------------------------------------
        # Paramètres Wazuh
        # --------------------------------------------------------------

        params: dict[str, str] = {
            "agents_list": normalized_agent_id,
            "wait_for_complete": "true",
        }

        # --------------------------------------------------------------
        # Appel API Wazuh
        # --------------------------------------------------------------

        try:

            with httpx.Client(
                verify=self.verify_ssl,
                timeout=self.timeout,
            ) as client:

                # ------------------------------------------------------
                # Authentification
                # ------------------------------------------------------

                token = self._get_token(client)

                # ------------------------------------------------------
                # Active Response
                # ------------------------------------------------------

                response = client.put(
                    f"{self.base_url}/active-response",
                    headers={
                        "Authorization": (
                            f"Bearer {token}"
                        ),
                        "Content-Type": (
                            "application/json"
                        ),
                    },
                    params=params,
                    content=json.dumps(
                        payload,
                        ensure_ascii=False,
                    ),
                )

        except httpx.HTTPError as exc:

            raise WazuhResponseError(
                f"Erreur réseau Wazuh: {exc}"
            ) from exc

        # --------------------------------------------------------------
        # Vérifier HTTP
        # --------------------------------------------------------------

        if response.status_code >= 400:

            raise WazuhResponseError(
                "Active Response Wazuh échouée: "
                f"{response.status_code} "
                f"{response.text}"
            )

        # --------------------------------------------------------------
        # Lire JSON
        # --------------------------------------------------------------

        try:

            body = response.json()

        except ValueError:

            body = {
                "raw": response.text
            }

        # --------------------------------------------------------------
        # Vérifier les erreurs retournées par Wazuh
        # --------------------------------------------------------------

        data = body.get(
            "data",
            {},
        )

        total_failed_items = data.get(
            "total_failed_items",
            0,
        )

        if total_failed_items:

            failed_items = data.get(
                "failed_items",
                [],
            )

            raise WazuhResponseError(
                "Wazuh a refusé l'Active Response : "
                f"{failed_items}"
            )

        # --------------------------------------------------------------
        # Résultat
        # --------------------------------------------------------------

        return {
            "mode": "live",
            "command": command,
            "wazuh_command": normalized_command,
            "agent_id": normalized_agent_id,
            "arguments": normalized_arguments,
            "status": "submitted",
            "wazuh_response": body,
        }

    # ==================================================================
    # COLLECT LOGS / TRIAGE
    # ==================================================================

    async def get_latest_triage_data(
        self,
        agent_id: str,
    ) -> dict[str, Any] | None:
        """
        Récupère la dernière collecte COLLECT_LOGS d'un agent
        depuis Wazuh Indexer.

        Les données proviennent de la règle Wazuh 100201 :

            rule.id = 100201

        Structure retournée :

        {
            "timestamp": "...",
            "computer": "KAISER",
            "action": "COLLECT_LOGS",
            "type": "triage_data",
            "agent": {...},
            "processes": [...],
            "network_connections": [...],
            "running_services": [...],
            "wazuh_alert_id": "...",
            "indexed_at": "..."
        }
        """

        # --------------------------------------------------------------
        # Vérification agent
        # --------------------------------------------------------------

        if not agent_id:
            raise WazuhResponseError(
                "agent_id est obligatoire pour récupérer "
                "les données de triage"
            )

        normalized_agent_id = str(
            agent_id
        ).strip()

        if not normalized_agent_id:
            raise WazuhResponseError(
                "agent_id invalide"
            )

        # --------------------------------------------------------------
        # Vérification configuration Indexer
        # --------------------------------------------------------------

        indexer_url = settings.WAZUH_INDEXER_URL.rstrip("/")

        if not indexer_url:
            raise WazuhResponseError(
                "WAZUH_INDEXER_URL n'est pas configuré"
            )

        if not settings.WAZUH_INDEXER_USER:
            raise WazuhResponseError(
                "WAZUH_INDEXER_USER n'est pas configuré"
            )

        if not settings.WAZUH_INDEXER_PASSWORD:
            raise WazuhResponseError(
                "WAZUH_INDEXER_PASSWORD n'est pas configuré"
            )

        # --------------------------------------------------------------
        # Endpoint Wazuh Indexer
        # --------------------------------------------------------------

        url = (
            f"{indexer_url}"
            "/wazuh-alerts-*/_search"
        )

        # --------------------------------------------------------------
        # Requête Elasticsearch / OpenSearch
        # --------------------------------------------------------------

        query: dict[str, Any] = {
            "size": 1,
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "query": {
                "bool": {
                    "must": [
                        {
                            "term": {
                                "rule.id": "100201"
                            }
                        },
                        {
                            "term": {
                                "agent.id": normalized_agent_id
                            }
                        },
                    ]
                }
            },
        }

        # --------------------------------------------------------------
        # Appel Indexer
        # --------------------------------------------------------------

        try:

            async with httpx.AsyncClient(
                verify=settings.WAZUH_INDEXER_VERIFY_SSL,
                timeout=settings.WAZUH_INDEXER_TIMEOUT,
                auth=(
                    settings.WAZUH_INDEXER_USER,
                    settings.WAZUH_INDEXER_PASSWORD,
                ),
            ) as client:

                response = await client.post(
                    url,
                    json=query,
                )

        except httpx.HTTPError as exc:

            raise WazuhResponseError(
                "Erreur réseau pendant la récupération "
                f"des données de triage Wazuh Indexer: {exc}"
            ) from exc

        # --------------------------------------------------------------
        # Vérifier HTTP
        # --------------------------------------------------------------

        if response.status_code >= 400:

            raise WazuhResponseError(
                "Wazuh Indexer a retourné une erreur : "
                f"{response.status_code} "
                f"{response.text}"
            )

        # --------------------------------------------------------------
        # Lire JSON
        # --------------------------------------------------------------

        try:

            result = response.json()

        except ValueError as exc:

            raise WazuhResponseError(
                "Réponse JSON invalide de Wazuh Indexer"
            ) from exc

        # --------------------------------------------------------------
        # Récupérer les résultats
        # --------------------------------------------------------------

        hits = (
            result
            .get("hits", {})
            .get("hits", [])
        )

        # Aucune collecte trouvée
        if not hits:
            return None

        # --------------------------------------------------------------
        # Première alerte = dernière collecte
        # --------------------------------------------------------------

        source = hits[0].get(
            "_source",
            {},
        )

        triage = source.get(
            "data",
            {},
        )

        if not isinstance(triage, dict):
            triage = {}

        # --------------------------------------------------------------
        # Construire une réponse propre pour FastAPI
        # --------------------------------------------------------------

        return {
            "timestamp": triage.get(
                "timestamp"
            ),
            "computer": triage.get(
                "computer"
            ),
            "action": triage.get(
                "action"
            ),
            "type": triage.get(
                "type"
            ),
            "agent": source.get(
                "agent",
                {},
            ),
            "processes": triage.get(
                "processes",
                [],
            ),
            "network_connections": triage.get(
                "network_connections",
                [],
            ),
            "running_services": triage.get(
                "running_services",
                [],
            ),
            "wazuh_alert_id": source.get(
                "id"
            ),
            "indexed_at": source.get(
                "@timestamp"
            ),
        }