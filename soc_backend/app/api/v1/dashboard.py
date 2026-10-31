from datetime import datetime, timedelta
import os
import time

import requests

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import get_db
from app.core.security import require_permission
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
)
def check_http_service(name: str, url: str):
    """
    Vérifie la disponibilité réelle d'un service HTTP/HTTPS.
    """
    start = time.perf_counter()

    try:
        response = requests.get(
            url,
            timeout=3,
            verify=False,
        )

        latency = round(
            (time.perf_counter() - start) * 1000
        )

        return {
            "name": name,
            "status": "UP",
            "latency": latency,
        }

    except requests.RequestException:
        latency = round(
            (time.perf_counter() - start) * 1000
        )

        return {
            "name": name,
            "status": "DOWN",
            "latency": latency,
        }


@router.get("/services")
def services_status(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    services = []

    # MariaDB : vérification réelle via SQLAlchemy
    start = time.perf_counter()

    try:
        db.execute(text("SELECT 1"))
        latency = round(
            (time.perf_counter() - start) * 1000
        )

        services.append({
            "name": "MariaDB",
            "status": "UP",
            "latency": latency,
        })

    except Exception:
        latency = round(
            (time.perf_counter() - start) * 1000
        )

        services.append({
            "name": "MariaDB",
            "status": "DOWN",
            "latency": latency,
        })

    # Services HTTP
    http_services = [
        (
            "TheHive",
            settings.THEHIVE_URL,
        ),
        (
            "Shuffle SOAR",
            settings.SHUFFLE_URL,
        ),
        (
            "FastAPI",
            os.getenv(
                "FASTAPI_URL",
                "http://127.0.0.1:8000/docs",
            ),
        ),
        (
            "OpenVAS",
            settings.OPENVAS_URL,
        ),
    ]

    for name, url in http_services:
        if not url:
            services.append({
                "name": name,
                "status": "UNKNOWN",
                "latency": None,
            })
            continue

        services.append(
            check_http_service(name, url)
        )

    # Wazuh Manager
    wazuh_url = settings.WAZUH_API_URL

    if wazuh_url:
        services.append(
            check_http_service(
                "Wazuh Manager",
                wazuh_url,
            )
        )
    else:
        services.append({
            "name": "Wazuh Manager",
            "status": "UNKNOWN",
            "latency": None,
        })

    return services


@router.get("/summary")
def summary(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    names = [
        "evenement",
        "alerte",
        "incident",
        "ioc",
        "actif",
        "vulnerabilite",
        "scan_vulnerabilite",
        "ticket_glpi",
    ]

    out = {}

    for n in names:
        try:
            out[n] = db.execute(
                text(f"SELECT COUNT(*) FROM `{n}`")
            ).scalar_one()
        except Exception:
            out[n] = 0

    return out


@router.get("/alerts-over-time")
def alerts_over_time(
    period: str = "24h",
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    if period == "7d":
        interval = "7 DAY"
        group_format = "%Y-%m-%d"
        label_format = "%d/%m"
        periods = 7
    elif period == "30d":
        interval = "30 DAY"
        group_format = "%Y-%m-%d"
        label_format = "%d/%m"
        periods = 30
    else:
        period = "24h"
        interval = "24 HOUR"
        group_format = "%Y-%m-%d %H:00:00"
        label_format = "%Hh"
        periods = 24

    rows = db.execute(
        text(
            f"""
            SELECT
                DATE_FORMAT(
                    date_creation,
                    '{group_format}'
                ) AS periode,
                COUNT(*) AS total
            FROM alerte
            WHERE date_creation >= NOW() - INTERVAL {interval}
            GROUP BY DATE_FORMAT(
                date_creation,
                '{group_format}'
            )
            ORDER BY periode ASC
            """
        )
    ).mappings().all()

    counts = {
        row["periode"]: int(row["total"])
        for row in rows
    }

    now = datetime.now()

    result = []

    if period == "24h":
        now = now.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        for i in range(23, -1, -1):
            point = now - timedelta(hours=i)
            key = point.strftime("%Y-%m-%d %H:00:00")

            result.append(
                {
                    "label": point.strftime("%Hh"),
                    "value": counts.get(key, 0),
                }
            )

    else:
        now = now.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        for i in range(periods - 1, -1, -1):
            point = now - timedelta(days=i)
            key = point.strftime("%Y-%m-%d")

            result.append(
                {
                    "label": point.strftime("%d/%m"),
                    "value": counts.get(key, 0),
                }
            )

    return result

@router.get("/alerts-by-severity")
def alerts_by_severity(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    rows = db.execute(
        text(
            """
            SELECT
                severite,
                COUNT(*) AS total
            FROM alerte
            GROUP BY severite
            ORDER BY
                CASE severite
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END
            """
        )
    ).mappings().all()

    counts = {
        row["severite"]: int(row["total"])
        for row in rows
    }

    severities = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    return [
        {
            "label": severity,
            "value": counts.get(severity, 0),
        }
        for severity in severities
    ]
@router.get("/incidents-by-status")
def incidents_by_status(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    rows = db.execute(
        text(
            """
            SELECT
                statut,
                COUNT(*) AS total
            FROM incident
            GROUP BY statut
            """
        )
    ).mappings().all()

    counts = {
        row["statut"]: int(row["total"])
        for row in rows
    }

    statuses = [
        "NEW",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED",
    ]

    return [
        {
            "label": status,
            "value": counts.get(status, 0),
        }
        for status in statuses
    ]
@router.get("/incidents-over-time")
def incidents_over_time(
    period: str = "24h",
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    if period == "7d":
        interval = "7 DAY"
        group_format = "%Y-%m-%d"
        periods = 7
    elif period == "30d":
        interval = "30 DAY"
        group_format = "%Y-%m-%d"
        periods = 30
    else:
        period = "24h"
        interval = "24 HOUR"
        group_format = "%Y-%m-%d %H:00:00"
        periods = 24

    rows = db.execute(
        text(
            f"""
            SELECT
                DATE_FORMAT(
                    date_creation,
                    '{group_format}'
                ) AS periode,
                COUNT(*) AS total
            FROM incident
            WHERE date_creation >= NOW() - INTERVAL {interval}
            GROUP BY DATE_FORMAT(
                date_creation,
                '{group_format}'
            )
            ORDER BY periode ASC
            """
        )
    ).mappings().all()

    counts = {
        row["periode"]: int(row["total"])
        for row in rows
    }

    now = datetime.now()

    result = []

    if period == "24h":
        now = now.replace(
            minute=0,
            second=0,
            microsecond=0,
        )

        for i in range(23, -1, -1):
            point = now - timedelta(hours=i)

            key = point.strftime(
                "%Y-%m-%d %H:00:00"
            )

            result.append(
                {
                    "label": point.strftime("%Hh"),
                    "value": counts.get(key, 0),
                }
            )

    else:
        now = now.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0,
        )

        for i in range(periods - 1, -1, -1):
            point = now - timedelta(days=i)

            key = point.strftime("%Y-%m-%d")

            result.append(
                {
                    "label": point.strftime("%d/%m"),
                    "value": counts.get(key, 0),
                }
            )

    return result
@router.get("/alerts-by-category")
def alerts_by_category(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    rows = db.execute(
        text(
            """
            SELECT
                rd.categorie AS label,
                COUNT(*) AS value
            FROM alerte a
            JOIN regle_detection rd
                ON a.id_regle_detection = rd.id_regle_detection
            WHERE rd.categorie IS NOT NULL
              AND rd.categorie <> ''
            GROUP BY rd.categorie
            ORDER BY value DESC
            """
        )
    ).mappings().all()

    return [
        {
            "label": row["label"],
            "value": int(row["value"]),
        }
        for row in rows
    ]
@router.get("/glpi-stats")
def glpi_stats(
    db: Session = Depends(get_db),
    _: object = Depends(require_permission("ALERT_READ")),
):
    """
    Statistiques des tickets GLPI stockés dans la base SOC.
    Les statuts sont synchronisés depuis GLPI.
    """

    try:
        total = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM ticket_glpi
                """
            )
        ).scalar_one()

        nouveaux = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM ticket_glpi
                WHERE statut = 'OPEN'
                """
            )
        ).scalar_one()

        en_traitement = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM ticket_glpi
                WHERE statut = 'PENDING'
                """
            )
        ).scalar_one()

        resolus = db.execute(
            text(
                """
                SELECT COUNT(*)
                FROM ticket_glpi
                WHERE statut IN ('RESOLVED', 'CLOSED')
                """
            )
        ).scalar_one()

        return {
            "total": int(total),
            "nouveaux": int(nouveaux),
            "en_traitement": int(en_traitement),
            "resolus": int(resolus),
        }

    except Exception as e:
        raise RuntimeError(
            f"Erreur récupération statistiques GLPI : {str(e)}"
        )