import httpx

from app.core.config import settings


class GLPIService:
    def __init__(self):
        self.base_url = settings.GLPI_URL.rstrip("/")
        self.app_token = settings.GLPI_APP_TOKEN
        self.user_token = settings.GLPI_API_TOKEN

    # ============================================================
    # INITIALISER UNE SESSION GLPI
    # ============================================================

    async def init_session(self) -> str:
        url = f"{self.base_url}/apirest.php/initSession"

        headers = {
            "Content-Type": "application/json",
            "App-Token": self.app_token,
            "Authorization": f"user_token {self.user_token}",
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                url,
                headers=headers,
            )

            response.raise_for_status()

            data = response.json()

        session_token = data.get("session_token")

        if not session_token:
            raise RuntimeError(
                "GLPI did not return a session_token"
            )

        return session_token

    # ============================================================
    # CRÉER UN TICKET
    # ============================================================

    async def create_ticket(
        self,
        name: str,
        content: str,
        urgency: int = 3,
    ) -> dict:

        session_token = await self.init_session()

        url = f"{self.base_url}/apirest.php/Ticket"

        headers = {
            "Content-Type": "application/json",
            "App-Token": self.app_token,
            "Session-Token": session_token,
        }

        payload = {
            "input": {
                "name": name,
                "content": content,
                "urgency": urgency,
            }
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:

                response = await client.post(
                    url,
                    headers=headers,
                    json=payload,
                )

                response.raise_for_status()

                return response.json()

        finally:
            await self.kill_session(session_token)

    # ============================================================
    # RÉCUPÉRER LA LISTE DES TICKETS
    # ============================================================

    async def get_tickets(
        self,
        limit: int = 50,
    ) -> list:

        session_token = await self.init_session()

        url = f"{self.base_url}/apirest.php/Ticket"

        headers = {
            "Content-Type": "application/json",
            "App-Token": self.app_token,
            "Session-Token": session_token,
        }

        # GLPI utilise Range pour limiter les résultats.
        # Exemple :
        # Range: 0-49 = 50 tickets
        range_end = limit - 1

        headers["Range"] = f"0-{range_end}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:

                response = await client.get(
                    url,
                    headers=headers,
                )

                response.raise_for_status()

                data = response.json()

                if isinstance(data, list):
                    return data

                return []

        finally:
            await self.kill_session(session_token)

    # ============================================================
    # RÉCUPÉRER UN TICKET
    # ============================================================

    async def get_ticket(
        self,
        ticket_id: int,
    ) -> dict | None:

        session_token = await self.init_session()

        url = (
            f"{self.base_url}/apirest.php/"
            f"Ticket/{ticket_id}"
        )

        headers = {
            "Content-Type": "application/json",
            "App-Token": self.app_token,
            "Session-Token": session_token,
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:

                response = await client.get(
                    url,
                    headers=headers,
                )

                if response.status_code == 404:
                    return None

                response.raise_for_status()

                data = response.json()

                if isinstance(data, dict):
                    return data

                return None

        finally:
            await self.kill_session(session_token)
            
    async def sync_ticket(self, ticket: dict) -> dict:
        """
        Transforme un ticket GLPI en données utilisables
        par la base locale du SOC.
        """

        status_map = {
            1: "OPEN",
            2: "PENDING",
            3: "PENDING",
            4: "PENDING",
            5: "RESOLVED",
            6: "CLOSED",
        }

        priority_map = {
            1: "LOW",
            2: "LOW",
            3: "MEDIUM",
            4: "HIGH",
            5: "HIGH",
            6: "HIGH",
        }

        glpi_id = ticket.get("id")

        if not glpi_id:
            return None

        return {
            "identificateur_externe_glpi": str(glpi_id),
            "titre": ticket.get("name") or "Sans titre",
            "description": ticket.get("content") or "",
            "priorite": priority_map.get(
                int(ticket.get("priority", 3)),
                "MEDIUM",
            ),
            "statut": status_map.get(
                int(ticket.get("status", 1)),
                "OPEN",
            ),
            "date_creation": ticket.get("date_creation"),
            "date_mise_a_jour": ticket.get("date_mod"),
            "date_cloture": ticket.get("closedate"),
        }

    # ============================================================
    # FERMER LA SESSION GLPI
    # ============================================================

    async def kill_session(
        self,
        session_token: str,
    ) -> None:

        url = f"{self.base_url}/apirest.php/killSession"

        headers = {
            "App-Token": self.app_token,
            "Session-Token": session_token,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:

            response = await client.get(
                url,
                headers=headers,
            )

            response.raise_for_status()