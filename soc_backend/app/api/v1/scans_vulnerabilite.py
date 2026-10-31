import re
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import MetaData, Table, select, insert, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/scan_vulnerabilite",
    tags=["scan_vulnerabilite"]
)

md = MetaData()
_table = None
_user_table = None


def get_table(db):
    global _table

    if _table is None:
        _table = Table(
            "scan_vulnerabilite",
            md,
            autoload_with=db.bind
        )

    return _table


def get_user_table(db):
    global _user_table

    if _user_table is None:
        _user_table = Table(
            "utilisateur",
            md,
            autoload_with=db.bind
        )

    return _user_table


def uuid_to_bytes(value):
    try:
        return uuid.UUID(str(value)).bytes
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(
            status_code=400,
            detail=f"UUID invalide: {value}"
        )


def normalize_value(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes=bytes(value)))

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return value


def row_to_dict(row):
    if row is None:
        return None

    return {
        key: normalize_value(value)
        for key, value in row._mapping.items()
    }


class GreenboneScanRequest(BaseModel):
    target: str
    profile: str = "full_fast"


def launch_greenbone_scan(target: str, profile: str):
    url = (
        f"{settings.GREENBONE_ADAPTER_URL.rstrip('/')}"
        "/scans"
    )

    try:
        response = httpx.post(
            url,
            json={
                "target": target,
                "profile": profile
            },
            timeout=30.0
        )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Greenbone Adapter inaccessible: {exc}"
        )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text

        raise HTTPException(
            status_code=502,
            detail=f"Erreur Greenbone: {detail}"
        )

    try:
        return response.json()

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Réponse Greenbone invalide"
        )


# ============================================================
# LANCEMENT SCAN
# ============================================================

@router.post(
    "/launch",
    status_code=201
)
def launch_scan(
    payload: GreenboneScanRequest,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("SCAN_CREATE")
    )
):
    t = get_table(db)
    user_table = get_user_table(db)

    utilisateur_id = uuid_to_bytes(
        current_user.id_utilisateur
    )

    utilisateur = db.execute(
        select(user_table).where(
            user_table.c.id_utilisateur == utilisateur_id
        )
    ).first()

    if not utilisateur:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur connecté introuvable"
        )

    greenbone = launch_greenbone_scan(
        payload.target,
        payload.profile
    )

    task_id = greenbone.get("task_id")

    if not task_id:
        raise HTTPException(
            status_code=502,
            detail="Greenbone n'a pas retourné de task_id"
        )

    report_id = None

    start_response = greenbone.get("start_response")

    if isinstance(start_response, str):
        match = re.search(
            r"<report_id>([^<]+)</report_id>",
            start_response
        )

        if match:
            report_id = match.group(1)

    scan_id = uuid.uuid4().bytes
    now = datetime.now(timezone.utc)

    description = (
        f"Scan Greenbone {payload.profile}. "
        f"Task ID: {task_id}."
    )

    if report_id:
        description += f" Report ID: {report_id}."

    values = {
        "id_scan": scan_id,
        "identificateur_externe_openvas": task_id,
        "id_utilisateur": utilisateur_id,
        "nom": f"Scan Greenbone - {payload.target}",
        "cible": payload.target,
        "date_debut": now,
        "date_fin": None,
        "statut": "RUNNING",
        "niveau_risque": None,
        "description": description,
    }

    db.execute(
        insert(t).values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_scan == scan_id
        )
    ).first()

    result = row_to_dict(row)

    result["greenbone"] = {
        "task_id": task_id,
        "report_id": report_id,
        "target": payload.target,
        "profile": payload.profile,
        "status": greenbone.get("status")
    }

    return result


# ============================================================
# CRUD SCAN
# ============================================================

class ScanVulnerabiliteCreate(BaseModel):
    identificateur_externe_openvas: str | None = None
    id_utilisateur: str
    nom: str
    cible: str | None = None
    date_debut: datetime
    date_fin: datetime | None = None
    statut: str = "RUNNING"
    niveau_risque: str | None = None
    description: str | None = None


@router.post(
    "",
    status_code=201,
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def create_scan(
    payload: ScanVulnerabiliteCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)
    user_table = get_user_table(db)

    utilisateur_id = uuid_to_bytes(
        payload.id_utilisateur
    )

    utilisateur = db.execute(
        select(user_table).where(
            user_table.c.id_utilisateur == utilisateur_id
        )
    ).first()

    if not utilisateur:
        raise HTTPException(
            status_code=404,
            detail="Utilisateur introuvable"
        )

    if payload.identificateur_externe_openvas:
        existing = db.execute(
            select(t).where(
                t.c.identificateur_externe_openvas
                == payload.identificateur_externe_openvas
            )
        ).first()

        if existing:
            raise HTTPException(
                status_code=409,
                detail="L'identificateur externe OpenVAS existe déjà"
            )

    scan_id = uuid.uuid4().bytes

    values = {
        "id_scan": scan_id,
        "identificateur_externe_openvas":
            payload.identificateur_externe_openvas,
        "id_utilisateur": utilisateur_id,
        "nom": payload.nom,
        "cible": payload.cible,
        "date_debut": payload.date_debut,
        "date_fin": payload.date_fin,
        "statut": payload.statut,
        "niveau_risque": payload.niveau_risque,
        "description": payload.description,
    }

    db.execute(
        insert(t).values(**values)
    )

    db.commit()

    row = db.execute(
        select(t).where(
            t.c.id_scan == scan_id
        )
    ).first()

    return row_to_dict(row)


# ============================================================
# STATUT GREENBONE
# ============================================================

@router.get(
    "/{task_id}/status",
    dependencies=[
        Depends(require_permission("SCAN_READ"))
    ]
)
def get_scan_status(
    task_id: str
):
    url = (
        f"{settings.GREENBONE_ADAPTER_URL.rstrip('/')}"
        f"/scans/{task_id}"
    )

    try:
        response = httpx.get(
            url,
            timeout=60.0
        )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Greenbone Adapter inaccessible: {exc}"
        )

    if response.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail="Tâche Greenbone introuvable"
        )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text

        raise HTTPException(
            status_code=502,
            detail=f"Erreur Greenbone: {detail}"
        )

    try:
        data = response.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Réponse Greenbone invalide"
        )

    return {
        "task_id": data.get("task_id", task_id),
        "statut": data.get("task_status"),
        "progress": data.get("progress", 0)
    }


# ============================================================
# ROUTES FRONTEND /vulnerability
# ============================================================

frontend_router = APIRouter(
    prefix="/vulnerability",
    tags=["vulnerability"]
)


@frontend_router.get(
    "/scans",
    dependencies=[
        Depends(require_permission("SCAN_READ"))
    ]
)
def frontend_list_scans(
    db: Session = Depends(get_db)
):
    t = get_table(db)

    rows = db.execute(
        select(t).order_by(
            t.c.date_debut.desc()
        )
    ).all()

    return [
        row_to_dict(row)
        for row in rows
    ]


@frontend_router.post(
    "/scan",
    status_code=201
)
def frontend_launch_scan(
    payload: GreenboneScanRequest,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("SCAN_CREATE")
    )
):
    return launch_scan(
        payload=payload,
        db=db,
        current_user=current_user
    )


# ============================================================
# GREENBONE REPORT
# ============================================================

@router.get(
    "/{task_id}/report",
    dependencies=[
        Depends(require_permission("SCAN_READ"))
    ]
)
def get_greenbone_report(
    task_id: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    row = db.execute(
        select(t).where(
            t.c.identificateur_externe_openvas == task_id
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail=f"Scan Greenbone introuvable: {task_id}"
        )

    scan = row._mapping

    description = scan.get("description") or ""

    match = re.search(
        r"Report ID:\s*([0-9a-fA-F-]{36})",
        description
    )

    if not match:
        raise HTTPException(
            status_code=404,
            detail="Report ID Greenbone introuvable pour ce scan"
        )

    report_id = match.group(1)

    url = (
        f"{settings.GREENBONE_ADAPTER_URL.rstrip('/')}"
        f"/reports/{report_id}"
    )

    try:
        response = httpx.get(
            url,
            timeout=60.0
        )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Greenbone Adapter inaccessible: {exc}"
        )

    if response.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail=f"Rapport Greenbone introuvable: {report_id}"
        )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text

        raise HTTPException(
            status_code=502,
            detail=f"Erreur Greenbone: {detail}"
        )

    try:
        report = response.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Réponse Greenbone invalide"
        )

    scan_id = scan["id_scan"]

    if isinstance(scan_id, (bytes, bytearray)):
        scan_id = str(
            uuid.UUID(bytes=bytes(scan_id))
        )

    return {
        "scan_id": scan_id,
        "task_id": task_id,
        "report_id": report_id,
        "target": scan.get("cible"),
        "profile": (
            "full_fast"
            if "full_fast" in description.lower()
            else None
        ),
        "result_count": report.get("result_count", 0),
        "results": report.get("results", [])
    }


# ============================================================
# IMPORT GREENBONE VULNERABILITIES
# ============================================================

@router.post(
    "/{task_id}/import",
    dependencies=[
        Depends(require_permission("SCAN_CREATE"))
    ]
)
def import_greenbone_results(
    task_id: str,
    db: Session = Depends(get_db)
):
    """
    Importe les vulnérabilités Greenbone d'un scan terminé
    dans vulnerabilite et resultat_vulnerabilite.
    """

    # --------------------------------------------------------
    # 1. Tables
    # --------------------------------------------------------

    scan_table = get_table(db)

    actif_table = Table(
        "actif",
        MetaData(),
        autoload_with=db.bind
    )

    vulnerabilite_table = Table(
        "vulnerabilite",
        MetaData(),
        autoload_with=db.bind
    )

    resultat_table = Table(
        "resultat_vulnerabilite",
        MetaData(),
        autoload_with=db.bind
    )

    # --------------------------------------------------------
    # 2. Recherche du scan
    # --------------------------------------------------------

    scan_row = db.execute(
        select(scan_table).where(
            scan_table.c.identificateur_externe_openvas
            == task_id
        )
    ).first()

    if not scan_row:
        raise HTTPException(
            status_code=404,
            detail=f"Scan Greenbone introuvable: {task_id}"
        )

    scan = scan_row._mapping

    scan_id = scan["id_scan"]

    description = scan.get("description") or ""

    # --------------------------------------------------------
    # 3. Extraction Report ID
    # --------------------------------------------------------

    match = re.search(
        r"Report ID:\s*([0-9a-fA-F-]{36})",
        description
    )

    if not match:
        raise HTTPException(
            status_code=404,
            detail="Report ID Greenbone introuvable"
        )

    report_id = match.group(1)

    # --------------------------------------------------------
    # 4. Récupération rapport
    # --------------------------------------------------------

    url = (
        f"{settings.GREENBONE_ADAPTER_URL.rstrip('/')}"
        f"/reports/{report_id}"
    )

    try:
        response = httpx.get(
            url,
            timeout=60.0
        )

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Greenbone Adapter inaccessible: {exc}"
        )

    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text

        raise HTTPException(
            status_code=502,
            detail=f"Erreur Greenbone: {detail}"
        )

    try:
        report = response.json()
    except Exception:
        raise HTTPException(
            status_code=502,
            detail="Réponse Greenbone invalide"
        )

    results = report.get("results", [])

    # --------------------------------------------------------
    # 5. Recherche actif
    # --------------------------------------------------------

    target = scan.get("cible")

    actif_row = db.execute(
        select(actif_table).where(
            actif_table.c.adresse_ip == target
        )
    ).first()

    if not actif_row:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Aucun actif trouvé pour l'adresse IP "
                f"{target}"
            )
        )

    actif = actif_row._mapping
    actif_id = actif["id_actif"]

    # --------------------------------------------------------
    # 6. Import
    # --------------------------------------------------------

    imported = []
    skipped = []
    duplicates = []

    for result in results:

        severity_value = result.get("severity")

        try:
            severity_value = float(severity_value)
        except (ValueError, TypeError):
            severity_value = 0.0

        # Résultat informatif
        if severity_value <= 0:
            skipped.append({
                "name": result.get("name"),
                "reason": "severity=0"
            })
            continue

        # Mapping Greenbone -> MariaDB
        if severity_value >= 9.0:
            severity = "CRITICAL"
        elif severity_value >= 7.0:
            severity = "HIGH"
        elif severity_value >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        cvss = result.get("cvss")

        if cvss is None:
            cvss = severity_value

        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = None

        cve = result.get("cve")
        name = result.get("name") or "Greenbone vulnerability"
        result_description = result.get("description")
        solution = result.get("solution")

        # ----------------------------------------------------
        # Recherche vulnérabilité existante
        # ----------------------------------------------------

        if cve:
            vulnerability_query = select(
                vulnerabilite_table
            ).where(
                vulnerabilite_table.c.cve == cve
            )
        else:
            vulnerability_query = select(
                vulnerabilite_table
            ).where(
                vulnerabilite_table.c.nom == name
            )

        vulnerability_row = db.execute(
            vulnerability_query
        ).first()

        if vulnerability_row:

            vulnerability = vulnerability_row._mapping

            vulnerability_id = vulnerability[
                "id_vulnerabilite"
            ]

        else:

            vulnerability_id = uuid.uuid4().bytes

            vulnerability_values = {
                "id_vulnerabilite": vulnerability_id,
                "cve": cve,
                "nom": name,
                "description": result_description,
                "severite": severity,
                "score_cvss": cvss,
                "solution": solution,
                "statut": "OPEN"
            }

            db.execute(
                insert(vulnerabilite_table).values(
                    **vulnerability_values
                )
            )

        # ----------------------------------------------------
        # Port / protocole
        # ----------------------------------------------------

        port_value = result.get("port")

        port = None
        protocole = None

        if port_value:

            port_text = str(port_value).lower()

            # IMPORTANT : HTTPS doit être testé avant HTTP
            if "https" in port_text:
                protocole = "HTTPS"
            elif "http" in port_text:
                protocole = "HTTP"
            elif "tcp" in port_text:
                protocole = "TCP"
            elif "udp" in port_text:
                protocole = "UDP"
            elif "icmp" in port_text:
                protocole = "ICMP"

            match_port = re.search(
                r"(?<!\d)(\d{1,5})(?!\d)",
                str(port_value)
            )

            if match_port:
                port = int(match_port.group(1))

            if protocole is None:
                protocole = "OTHER"

        # ----------------------------------------------------
        # Vérification doublon
        # ----------------------------------------------------

        duplicate_query = select(
            resultat_table
        ).where(
            resultat_table.c.id_scan == scan_id,
            resultat_table.c.id_actif == actif_id,
            resultat_table.c.id_vulnerabilite
            == vulnerability_id
        )

        if port is not None:
            duplicate_query = duplicate_query.where(
                resultat_table.c.port == port
            )

        existing_result = db.execute(
            duplicate_query
        ).first()

        if existing_result:

            duplicates.append({
                "name": name,
                "cve": cve
            })

            continue

        # ----------------------------------------------------
        # Création résultat
        # ----------------------------------------------------

        result_id = uuid.uuid4().bytes

        result_values = {
            "id_resultat": result_id,
            "id_scan": scan_id,
            "id_actif": actif_id,
            "id_vulnerabilite": vulnerability_id,
            "port": port,
            "protocole": protocole,
            "score_cvss": cvss,
            "severite": severity,
            "preuve": result_description,
            "solution": solution,
            "statut": "DETECTED"
        }

        db.execute(
            insert(resultat_table).values(
                **result_values
            )
        )

        imported.append({
            "id_resultat": str(
                uuid.UUID(bytes=result_id)
            ),
            "name": name,
            "cve": cve,
            "host": result.get("host"),
            "port": port,
            "protocole": protocole,
            "severity": severity,
            "cvss": cvss
        })

    # --------------------------------------------------------
    # 7. Mise à jour scan
    # --------------------------------------------------------

    now = datetime.now(timezone.utc)

    risk = (
        "CRITICAL"
        if any(
            item["severity"] == "CRITICAL"
            for item in imported
        )
        else "HIGH"
        if any(
            item["severity"] == "HIGH"
            for item in imported
        )
        else "MEDIUM"
        if any(
            item["severity"] == "MEDIUM"
            for item in imported
        )
        else "LOW"
        if imported
        else None
    )

    db.execute(
        update(scan_table)
        .where(
            scan_table.c.id_scan == scan_id
        )
        .values(
            statut="DONE",
            date_fin=now,
            niveau_risque=risk
        )
    )

    db.commit()

    # --------------------------------------------------------
    # 8. Réponse
    # --------------------------------------------------------

    return {
        "status": "ok",
        "scan_id": str(
            uuid.UUID(bytes=bytes(scan_id))
        ),
        "task_id": task_id,
        "report_id": report_id,
        "target": target,
        "imported_count": len(imported),
        "duplicate_count": len(duplicates),
        "skipped_count": len(skipped),
        "imported": imported,
        "duplicates": duplicates,
        "skipped": skipped
    }