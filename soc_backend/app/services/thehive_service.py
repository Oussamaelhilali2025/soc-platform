import requests

from app.core.config import settings


class TheHiveError(Exception):
    pass


class TheHiveService:

    def __init__(self):
        self.base_url = settings.THEHIVE_URL.rstrip("/")
        self.api_key = settings.THEHIVE_API_KEY

        if not self.api_key:
            raise TheHiveError(
                "THEHIVE_API_KEY n'est pas configurée."
            )

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def create_alert(
        self,
        *,
        title: str,
        description: str,
        source: str,
        source_ref: str,
        severity: int = 2,
        tlp: int = 2,
        pap: int = 2,
        alert_type: str = "soc-platform",
        tags: list[str] | None = None,
    ):

        payload = {
            "type": alert_type,
            "source": source,
            "sourceRef": source_ref,
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "pap": pap,
            "tags": tags or [],
        }

        response = requests.post(
            f"{self.base_url}/api/v1/alert",
            headers=self._headers(),
            json=payload,
            timeout=30,
        )

        if not response.ok:
            raise TheHiveError(
                f"TheHive create alert failed "
                f"({response.status_code}): "
                f"{response.text}"
            )

        return response.json()

    def create_case_from_alert(
        self,
        alert_id: str,
        *,
        title: str | None = None,
        description: str | None = None,
        severity: int | None = None,
        tlp: int = 2,
        pap: int = 2,
    ):

        payload = {
            "tlp": tlp,
            "pap": pap,
        }

        if title:
            payload["title"] = title

        if description:
            payload["description"] = description

        if severity is not None:
            payload["severity"] = severity

        response = requests.post(
            f"{self.base_url}/api/v1/alert/"
            f"{alert_id}/case",
            headers=self._headers(),
            json=payload,
            timeout=30,
        )

        if not response.ok:
            raise TheHiveError(
                f"TheHive create case failed "
                f"({response.status_code}): "
                f"{response.text}"
            )

        return response.json()
    def update_case_status(
    self,
    case_id: str,
    status: str,
):
        print(
        "THEHIVE UPDATE CALLED:",
        case_id,
        status,
        flush=True,
    )

        status_map = {
        "NEW": "New",
        "IN_PROGRESS": "InProgress",
        "RESOLVED": "TruePositive",
        "CLOSED": "TruePositive",
    }

        thehive_status = status_map.get(status)

        if not thehive_status:
            raise TheHiveError(
            f"Statut incident invalide : {status}"
        )

        payload = {
        "status": thehive_status
    }

        if status in {"RESOLVED", "CLOSED"}:
            payload["summary"] = "Cloture SOC"

        response = requests.patch(
        f"{self.base_url}/api/v1/case/{case_id}",
        headers=self._headers(),
        json=payload,
        timeout=30,
    )

        print(
        "THEHIVE STATUS RESPONSE:",
        response.status_code,
        response.text,
        flush=True,
    )

        if not response.ok:
            raise TheHiveError(
            f"TheHive update case status failed "
            f"({response.status_code}): "
            f"{response.text}"
        )

        if response.text:
            try:
                return response.json()
            except ValueError:
                return None

        return None