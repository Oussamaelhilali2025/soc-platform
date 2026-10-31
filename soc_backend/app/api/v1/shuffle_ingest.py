from datetime import datetime, timezone
from typing import Any
import json
import uuid
import ipaddress
import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.alerte import Alerte
from app.models.ioc import IOC
from app.models.evaluation_risque import EvaluationRisque
from app.models.incident import Incident
from app.models.evenement import Evenement
from app.models.agent import Agent
from app.services.mitre_service import sync_event_mitre


router = APIRouter(
    prefix="/ingest",
    tags=["ingestion"]
)


# ============================================================
# TYPES IOC SUPPORTÉS PAR LA BASE
# ============================================================

SUPPORTED_DB_IOC_TYPES = {
    "IP",
    "DOMAIN",
    "URL",
    "HASH_MD5",
    "HASH_SHA1",
    "HASH_SHA256",
    "FILE",
    "EMAIL",
}


# ============================================================
# UTILITAIRES
# ============================================================

def normalize_object(value: Any) -> Any:

    if value is None:
        return None

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return None

        try:
            parsed = json.loads(value)
            return normalize_object(parsed)

        except (
            json.JSONDecodeError,
            TypeError,
        ):
            return value

    if isinstance(value, dict):

        if (
            "data" in value
            and len(value) == 1
        ):
            return normalize_object(
                value["data"]
            )

        return {
            key: normalize_object(item)
            for key, item in value.items()
        }

    if isinstance(value, list):

        return [
            normalize_object(item)
            for item in value
        ]

    return value


def parse_datetime(value: Any) -> datetime:

    if isinstance(value, datetime):

        if value.tzinfo is None:
            return value

        return value.astimezone(
            timezone.utc
        ).replace(
            tzinfo=None
        )

    if value is None:
        return datetime.utcnow()

    if isinstance(
        value,
        (int, float),
    ):

        try:

            if value > 100000000000:

                return datetime.fromtimestamp(
                    value / 1000,
                    tz=timezone.utc,
                ).replace(
                    tzinfo=None
                )

            return datetime.fromtimestamp(
                value,
                tz=timezone.utc,
            ).replace(
                tzinfo=None
            )

        except Exception:

            return datetime.utcnow()

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return datetime.utcnow()

        try:

            parsed = datetime.fromisoformat(
                value.replace(
                    "Z",
                    "+00:00",
                )
            )

            if parsed.tzinfo is not None:

                parsed = parsed.astimezone(
                    timezone.utc
                ).replace(
                    tzinfo=None
                )

            return parsed

        except Exception:
            pass

    return datetime.utcnow()


def normalize_severity(value: Any) -> str:

    if value is None:
        return "MEDIUM"

    value = str(
        value
    ).strip().upper()

    mapping = {

        "1": "LOW",
        "2": "LOW",

        "3": "MEDIUM",

        "4": "HIGH",

        "5": "CRITICAL",

        "INFO": "LOW",
        "INFORMATION": "LOW",

        "LOW": "LOW",

        "MEDIUM": "MEDIUM",
        "MODERATE": "MEDIUM",

        "HIGH": "HIGH",
        "SEVERE": "HIGH",

        "CRITICAL": "CRITICAL",
        "CRITIQUE": "CRITICAL",
    }

    return mapping.get(
        value,
        "MEDIUM",
    )


# ============================================================
# NORMALISATION TYPE IOC INTERNE
# ============================================================

def normalize_ioc_type(value: Any) -> str:

    if value is None:
        return "unknown"

    value = str(
        value
    ).strip().lower()

    mapping = {

        "ip": "ip",
        "ip_address": "ip",
        "ipv4": "ip",
        "ipv6": "ip",

        "url": "url",
        "url_address": "url",

        "domain": "domain",
        "hostname": "domain",
        "fqdn": "domain",

        "hash": "hash",
        "sha256": "hash",
        "sha1": "hash",
        "md5": "hash",
        "file_hash": "hash",
        "filehash": "hash",

        "hash_sha256": "hash",
        "hash_sha1": "hash",
        "hash_md5": "hash",

        "file": "file_path",
        "filepath": "file_path",
        "file_path": "file_path",
        "path": "file_path",

        "email": "email",
        "mail": "email",

        "cmd": "command",
        "command": "command",
        "command_line": "command",
    }

    return mapping.get(
        value,
        value,
    )


# ============================================================
# TYPE IOC POUR MARIA DB
# ============================================================

def get_database_ioc_type(
    ioc_type: Any,
    value: Any = None,
) -> str | None:

    normalized = normalize_ioc_type(
        ioc_type
    )

    if normalized == "ip":
        return "IP"

    if normalized == "domain":
        return "DOMAIN"

    if normalized == "url":
        return "URL"

    if normalized == "file_path":
        return "FILE"

    if normalized == "email":
        return "EMAIL"

    if normalized == "hash":

        clean_value = clean_observable_value(
            value
        )

        if not clean_value:
            return None

        hash_value = clean_value.strip()

        if re.fullmatch(
            r"[A-Fa-f0-9]{64}",
            hash_value,
        ):
            return "HASH_SHA256"

        if re.fullmatch(
            r"[A-Fa-f0-9]{40}",
            hash_value,
        ):
            return "HASH_SHA1"

        if re.fullmatch(
            r"[A-Fa-f0-9]{32}",
            hash_value,
        ):
            return "HASH_MD5"

        print(
            "DEBUG IOC HASH INVALID:",
            hash_value,
            flush=True,
        )

        return None

    upper_type = str(
        ioc_type
    ).strip().upper()

    if upper_type in SUPPORTED_DB_IOC_TYPES:
        return upper_type

    return None


def clean_observable_value(
    value: Any,
) -> str | None:

    if value is None:
        return None

    if isinstance(
        value,
        (dict, list),
    ):
        return None

    value = str(
        value
    ).strip()

    if not value:
        return None

    invalid_values = {

        "NULL",
        "NONE",
        "N/A",
        "NA",
        "$VARIABLE",
        "$VARIABLES",
        "UNDEFINED",
        "UNKNOWN",
        "NIL",
    }

    if value.upper() in invalid_values:
        return None

    if (
        value.startswith("[")
        and value.endswith("]")
    ):

        value = value[1:-1].strip()

    if not value:
        return None

    return value


def normalize_bool(
    value: Any,
) -> bool | None:

    if value is None:
        return None

    if isinstance(
        value,
        bool,
    ):
        return value

    if isinstance(
        value,
        (int, float),
    ):
        return bool(value)

    value = str(
        value
    ).strip().lower()

    if value in {
        "true",
        "1",
        "yes",
        "oui",
        "y",
    }:
        return True

    if value in {
        "false",
        "0",
        "no",
        "non",
        "n",
    }:
        return False

    return None


def uuid_to_bytes(
    value: Any,
):

    if value is None:
        return None

    if isinstance(
        value,
        bytes,
    ):
        return value

    if isinstance(
        value,
        uuid.UUID,
    ):
        return value.bytes

    if hasattr(
        value,
        "bytes",
    ):

        try:

            return value.bytes

        except Exception:
            pass

    if isinstance(
        value,
        str,
    ):

        value = value.strip()

        try:

            return uuid.UUID(
                value
            ).bytes

        except Exception:
            pass

        try:

            return bytes.fromhex(
                value.replace(
                    "-",
                    "",
                )
            )

        except Exception:
            pass

    return value


def first_value(
    data: Any,
    keys: list[str],
) -> Any:

    if isinstance(
        data,
        dict,
    ):

        for key in keys:

            if (
                key in data
                and data[key] is not None
            ):

                return data[key]

        for value in data.values():

            result = first_value(
                value,
                keys,
            )

            if result is not None:
                return result

    elif isinstance(
        data,
        list,
    ):

        for item in data:

            result = first_value(
                item,
                keys,
            )

            if result is not None:
                return result

    return None


def find_nested_dict(
    data: Any,
    keys: list[str],
) -> dict | None:

    if isinstance(
        data,
        dict,
    ):

        if any(
            key in data
            for key in keys
        ):
            return data

        for value in data.values():

            result = find_nested_dict(
                value,
                keys,
            )

            if result is not None:
                return result

    elif isinstance(
        data,
        list,
    ):

        for item in data:

            result = find_nested_dict(
                item,
                keys,
            )

            if result is not None:
                return result

    return None


def serialize_raw_response(
    value: Any,
) -> str | None:

    if value is None:
        return None

    try:

        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    except Exception:

        return str(value)


# ============================================================
# MITRE ATT&CK
# ============================================================

MITRE_TECHNIQUE_ID_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    re.IGNORECASE,
)


def is_mitre_technique_id(
    value: Any,
) -> bool:

    if value is None:
        return False

    value = str(
        value
    ).strip()

    return bool(
        MITRE_TECHNIQUE_ID_PATTERN.fullmatch(
            value
        )
    )


def normalize_mitre_string(
    value: Any,
) -> str | None:

    if value is None:
        return None

    if isinstance(
        value,
        (dict, list),
    ):
        return None

    value = str(
        value
    ).strip()

    if not value:
        return None

    return value


def split_mitre_values(
    value: Any,
) -> list[str]:

    value = normalize_object(
        value
    )

    if value is None:
        return []

    if isinstance(
        value,
        list,
    ):

        result = []

        for item in value:

            result.extend(
                split_mitre_values(
                    item
                )
            )

        return result

    if isinstance(
        value,
        dict,
    ):

        result = []

        candidate_keys = [
            "id",
            "ids",
            "technique_id",
            "technique_ids",
            "technique",
            "techniques",
            "technique_name",
            "technique_names",
        ]

        for key in candidate_keys:

            if key in value:

                result.extend(
                    split_mitre_values(
                        value.get(key)
                    )
                )

        return result

    value = str(
        value
    ).strip()

    if not value:
        return []

    # Les valeurs reçues par Shuffle peuvent être :
    #
    # T1070.004
    # T1070.004, T1485
    # File Deletion, Data Destruction
    #
    # On accepte aussi "|" et ";".
    if "," in value:

        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    if ";" in value:

        return [
            item.strip()
            for item in value.split(";")
            if item.strip()
        ]

    if "|" in value:

        return [
            item.strip()
            for item in value.split("|")
            if item.strip()
        ]

    return [value]


def extract_mitre_technique_values(
    mitre_data: Any,
) -> list[str]:

    mitre_data = normalize_object(
        mitre_data
    )

    if not mitre_data:
        return []

    values = []

    if isinstance(
        mitre_data,
        dict,
    ):

        technique_keys = [
            "id",
            "ids",
            "technique_id",
            "technique_ids",
            "techniques_ids",
            "technique",
            "techniques",
            "technique_name",
            "technique_names",
        ]

        for key in technique_keys:

            if key in mitre_data:

                values.extend(
                    split_mitre_values(
                        mitre_data.get(key)
                    )
                )

        # Certains payloads peuvent contenir
        # une structure imbriquée.
        if not values:

            for value in mitre_data.values():

                if isinstance(
                    value,
                    (dict, list),
                ):

                    values.extend(
                        extract_mitre_technique_values(
                            value
                        )
                    )

    elif isinstance(
        mitre_data,
        list,
    ):

        for item in mitre_data:

            values.extend(
                split_mitre_values(
                    item
                )
            )

    else:

        values.extend(
            split_mitre_values(
                mitre_data
            )
        )

    result = []

    seen = set()

    for value in values:

        value = normalize_mitre_string(
            value
        )

        if not value:
            continue

        key = value.lower()

        if key in seen:
            continue

        seen.add(key)

        result.append(
            value
        )

    return result


def resolve_mitre_technique_ids(
    db: Session,
    mitre_values: list[str],
) -> list[str]:

    resolved = []

    seen = set()

    for value in mitre_values:

        value = str(
            value
        ).strip()

        if not value:
            continue

        # ----------------------------------------------------
        # Recherche directe par ID
        # ----------------------------------------------------

        if is_mitre_technique_id(
            value
        ):

            row = db.execute(
                text(
                    """
                    SELECT id_technique
                    FROM technique_mitre
                    WHERE LOWER(id_technique)
                          = LOWER(:value)
                    LIMIT 1
                    """
                ),
                {
                    "value": value,
                },
            ).first()

            if row:

                technique_id = str(
                    row[0]
                ).strip()

                if technique_id not in seen:

                    seen.add(
                        technique_id
                    )

                    resolved.append(
                        technique_id
                    )

            continue

        # ----------------------------------------------------
        # Recherche exacte par nom
        # ----------------------------------------------------

        row = db.execute(
            text(
                """
                SELECT id_technique
                FROM technique_mitre
                WHERE LOWER(TRIM(nom))
                      = LOWER(TRIM(:value))
                LIMIT 1
                """
            ),
            {
                "value": value,
            },
        ).first()

        if row:

            technique_id = str(
                row[0]
            ).strip()

            if technique_id not in seen:

                seen.add(
                    technique_id
                )

                resolved.append(
                    technique_id
                )

            continue

        # ----------------------------------------------------
        # Recherche insensible à la casse avec LIKE
        # comme dernier niveau de résolution.
        # ----------------------------------------------------

        rows = db.execute(
            text(
                """
                SELECT
                    id_technique,
                    nom
                FROM technique_mitre
                WHERE LOWER(nom)
                      LIKE LOWER(:value)
                """
            ),
            {
                "value": value,
            },
        ).all()

        for candidate in rows:

            candidate_id = str(
                candidate[0]
            ).strip()

            candidate_name = (
                str(
                    candidate[1]
                ).strip()
                if candidate[1] is not None
                else ""
            )

            if (
                candidate_name.lower()
                == value.lower()
            ):

                if candidate_id not in seen:

                    seen.add(
                        candidate_id
                    )

                    resolved.append(
                        candidate_id
                    )

                break

    return resolved


def sync_event_mitre(
    db: Session,
    evenement_id: Any,
    mitre_data: Any,
    source_detection: str = "Wazuh",
    confiance: int = 100,
) -> list[str]:

    """
    Synchronise la relation :

        evenement
             |
             v
        evenement_mitre
             |
             v
        technique_mitre

    Aucun mapping OWASP -> MITRE n'est effectué.

    Les techniques sont uniquement résolues à partir
    des valeurs MITRE reçues depuis Shuffle/Wazuh et
    présentes dans technique_mitre.
    """

    if not evenement_id:
        return []

    id_evenement_bin = uuid_to_bytes(
        evenement_id
    )

    if not id_evenement_bin:
        print(
            "DEBUG MITRE SKIPPED:",
            "UUID événement invalide",
            evenement_id,
            flush=True,
        )

        return []

    mitre_data = normalize_object(
        mitre_data
    )

    # --------------------------------------------------------
    # Supprimer les anciennes relations MITRE de cet événement
    # afin d'éviter de conserver une ancienne classification.
    # --------------------------------------------------------

    db.execute(
        text(
            """
            DELETE FROM evenement_mitre
            WHERE id_evenement = :id_evenement
            """
        ),
        {
            "id_evenement":
                id_evenement_bin,
        },
    )

    if not mitre_data:

        print(
            "DEBUG MITRE SYNC:",
            "aucune donnée MITRE",
            evenement_id,
            flush=True,
        )

        return []

    raw_values = (
        extract_mitre_technique_values(
            mitre_data
        )
    )

    if not raw_values:

        print(
            "DEBUG MITRE SYNC:",
            "aucune technique trouvée",
            mitre_data,
            flush=True,
        )

        return []

    technique_ids = (
        resolve_mitre_technique_ids(
            db,
            raw_values,
        )
    )

    if not technique_ids:

        print(
            "DEBUG MITRE SYNC:",
            "aucune technique correspondante en base",
            raw_values,
            flush=True,
        )

        return []

    inserted = []

    for technique_id in technique_ids:

        existing = db.execute(
            text(
                """
                SELECT 1
                FROM evenement_mitre
                WHERE id_evenement = :id_evenement
                  AND id_technique = :id_technique
                LIMIT 1
                """
            ),
            {
                "id_evenement":
                    id_evenement_bin,

                "id_technique":
                    technique_id,
            },
        ).first()

        if existing:
            continue

        db.execute(
            text(
                """
                INSERT INTO evenement_mitre
                (
                    id_evenement,
                    id_technique,
                    source_detection,
                    confiance
                )
                VALUES
                (
                    :id_evenement,
                    :id_technique,
                    :source_detection,
                    :confiance
                )
                """
            ),
            {
                "id_evenement":
                    id_evenement_bin,

                "id_technique":
                    technique_id,

                "source_detection":
                    source_detection,

                "confiance":
                    confiance,
            },
        )

        inserted.append(
            technique_id
        )

    print(
        "DEBUG EVENEMENT-MITRE SYNC:",
        "event=",
        evenement_id,
        "raw=",
        raw_values,
        "resolved=",
        inserted,
        flush=True,
    )

    return inserted


# ============================================================
# VALIDATION IP
# ============================================================

def is_private_or_invalid_ip(
    value: Any,
) -> bool:

    value = clean_observable_value(
        value
    )

    if not value:
        return True

    try:

        ip = ipaddress.ip_address(
            value
        )

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )

    except ValueError:

        return True


# ============================================================
# VIRUSTOTAL
# ============================================================

def save_virustotal_intelligence(
    db: Session,
    ioc: IOC,
    virustotal_data: Any,
) -> bool:

    if not virustotal_data:
        return False

    normalized = normalize_object(
        virustotal_data
    )

    if normalized is None:
        return False

    stats = find_nested_dict(
        normalized,
        [
            "last_analysis_stats",
            "lastAnalysisStats",
            "malicious",
            "suspicious",
            "harmless",
            "undetected",
            "positives",
            "total",
        ],
    )

    if stats is None:
        stats = normalized

    malicious_count = first_value(
        stats,
        [
            "malicious",
            "malicious_count",
            "maliciousCount",
            "positives",
        ],
    )

    suspicious_count = first_value(
        stats,
        [
            "suspicious",
            "suspicious_count",
            "suspiciousCount",
        ],
    )

    harmless_count = first_value(
        stats,
        [
            "harmless",
            "harmless_count",
            "harmlessCount",
        ],
    )

    undetected_count = first_value(
        stats,
        [
            "undetected",
            "undetected_count",
            "undetectedCount",
        ],
    )

    try:
        malicious_count = int(
            malicious_count
            if malicious_count is not None
            else 0
        )
    except Exception:
        malicious_count = 0

    try:
        suspicious_count = int(
            suspicious_count
            if suspicious_count is not None
            else 0
        )
    except Exception:
        suspicious_count = 0

    try:
        harmless_count = int(
            harmless_count
            if harmless_count is not None
            else 0
        )
    except Exception:
        harmless_count = 0

    try:
        undetected_count = int(
            undetected_count
            if undetected_count is not None
            else 0
        )
    except Exception:
        undetected_count = 0

    total_engines = first_value(
        normalized,
        [
            "total_engines",
            "totalEngines",
            "total",
        ],
    )

    try:

        if total_engines is not None:

            total_engines = int(
                total_engines
            )

        else:

            total_engines = (
                malicious_count
                + suspicious_count
                + harmless_count
                + undetected_count
            )

    except Exception:

        total_engines = (
            malicious_count
            + suspicious_count
            + harmless_count
            + undetected_count
        )

    if total_engines <= 0:

        print(
            "DEBUG TI VIRUSTOTAL SKIPPED:",
            "aucun moteur disponible",
            "IOC:",
            ioc.type_ioc,
            ioc.valeur,
            flush=True,
        )

        return False

    reputation = first_value(
        normalized,
        ["reputation"],
    )

    last_analysis_date = first_value(
        normalized,
        [
            "last_analysis_date",
            "lastAnalysisDate",
        ],
    )

    permalink = first_value(
        normalized,
        ["permalink"],
    )

    if permalink is None:

        links = find_nested_dict(
            normalized,
            ["self"],
        )

        if links:
            permalink = links.get(
                "self"
            )

    try:

        reputation = (
            int(reputation)
            if reputation is not None
            else None
        )

    except Exception:

        reputation = None

    last_analysis_datetime = None

    if last_analysis_date is not None:

        last_analysis_datetime = parse_datetime(
            last_analysis_date
        )

    raw_response = serialize_raw_response(
        normalized
    )

    id_ioc_bin = uuid_to_bytes(
        ioc.id_ioc
    )

    if not id_ioc_bin:

        print(
            "DEBUG TI VIRUSTOTAL SKIPPED:",
            "IOC ID invalide",
            flush=True,
        )

        return False

    existing = db.execute(
        text(
            """
            SELECT id_ti_vt
            FROM threat_intelligence_vt
            WHERE id_ioc = :id_ioc
            LIMIT 1
            """
        ),
        {
            "id_ioc": id_ioc_bin,
        },
    ).first()

    params = {

        "malicious_count":
            malicious_count,

        "suspicious_count":
            suspicious_count,

        "harmless_count":
            harmless_count,

        "undetected_count":
            undetected_count,

        "total_engines":
            total_engines,

        "reputation":
            reputation,

        "last_analysis_date":
            last_analysis_datetime,

        "permalink":
            clean_observable_value(
                permalink
            ),

        "raw_response":
            raw_response,

        "id_ioc":
            id_ioc_bin,
    }

    if existing:

        db.execute(
            text(
                """
                UPDATE threat_intelligence_vt
                SET
                    malicious_count = :malicious_count,
                    suspicious_count = :suspicious_count,
                    harmless_count = :harmless_count,
                    undetected_count = :undetected_count,
                    total_engines = :total_engines,
                    reputation = :reputation,
                    last_analysis_date = :last_analysis_date,
                    permalink = :permalink,
                    raw_response = :raw_response
                WHERE id_ioc = :id_ioc
                """
            ),
            params,
        )

    else:

        db.execute(
            text(
                """
                INSERT INTO threat_intelligence_vt
                (
                    id_ti_vt,
                    id_ioc,
                    malicious_count,
                    suspicious_count,
                    harmless_count,
                    undetected_count,
                    total_engines,
                    reputation,
                    last_analysis_date,
                    permalink,
                    raw_response
                )
                VALUES
                (
                    :id_ti_vt,
                    :id_ioc,
                    :malicious_count,
                    :suspicious_count,
                    :harmless_count,
                    :undetected_count,
                    :total_engines,
                    :reputation,
                    :last_analysis_date,
                    :permalink,
                    :raw_response
                )
                """
            ),
            {
                **params,
                "id_ti_vt":
                    uuid.uuid4().bytes,
            },
        )

    print(
        "DEBUG TI VIRUSTOTAL SAVED:",
        ioc.type_ioc,
        ioc.valeur,
        "engines=",
        total_engines,
        "malicious=",
        malicious_count,
        "suspicious=",
        suspicious_count,
        "harmless=",
        harmless_count,
        "undetected=",
        undetected_count,
        flush=True,
    )

    return True


# ============================================================
# ABUSEIPDB
# ============================================================

def save_abuseipdb_intelligence(
    db: Session,
    ioc: IOC,
    abuseipdb_data: Any,
) -> bool:

    if not abuseipdb_data:
        return False

    normalized = normalize_object(
        abuseipdb_data
    )

    if normalized is None:
        return False

    abuse_confidence_score = first_value(
        normalized,
        [
            "abuse_confidence_score",
            "abuseConfidenceScore",
        ],
    )

    total_reports = first_value(
        normalized,
        [
            "total_reports",
            "totalReports",
        ],
    )

    num_distinct_users = first_value(
        normalized,
        [
            "num_distinct_users",
            "numDistinctUsers",
        ],
    )

    country_code = first_value(
        normalized,
        [
            "country_code",
            "countryCode",
        ],
    )

    country_name = first_value(
        normalized,
        [
            "country_name",
            "countryName",
        ],
    )

    isp = first_value(
        normalized,
        ["isp"],
    )

    usage_type = first_value(
        normalized,
        [
            "usage_type",
            "usageType",
        ],
    )

    is_tor = first_value(
        normalized,
        [
            "is_tor",
            "isTor",
        ],
    )

    last_reported_at = first_value(
        normalized,
        [
            "last_reported_at",
            "lastReportedAt",
        ],
    )

    try:

        abuse_confidence_score = int(
            abuse_confidence_score
            if abuse_confidence_score is not None
            else 0
        )

    except Exception:

        abuse_confidence_score = 0

    try:

        total_reports = int(
            total_reports
            if total_reports is not None
            else 0
        )

    except Exception:

        total_reports = 0

    try:

        num_distinct_users = int(
            num_distinct_users
            if num_distinct_users is not None
            else 0
        )

    except Exception:

        num_distinct_users = 0

    normalized_is_tor = normalize_bool(
        is_tor
    )

    if normalized_is_tor is None:
        normalized_is_tor = False

    last_reported_datetime = None

    if last_reported_at is not None:

        last_reported_datetime = parse_datetime(
            last_reported_at
        )

    raw_response = serialize_raw_response(
        normalized
    )

    id_ioc_bin = uuid_to_bytes(
        ioc.id_ioc
    )

    if not id_ioc_bin:

        print(
            "DEBUG TI ABUSEIPDB SKIPPED:",
            "IOC ID invalide",
            flush=True,
        )

        return False

    existing = db.execute(
        text(
            """
            SELECT id_ti_abuse
            FROM threat_intelligence_abuseipdb
            WHERE id_ioc = :id_ioc
            LIMIT 1
            """
        ),
        {
            "id_ioc": id_ioc_bin,
        },
    ).first()

    params = {

        "abuse_confidence_score":
            abuse_confidence_score,

        "total_reports":
            total_reports,

        "num_distinct_users":
            num_distinct_users,

        "country_code":
            clean_observable_value(
                country_code
            ),

        "country_name":
            clean_observable_value(
                country_name
            ),

        "isp":
            clean_observable_value(
                isp
            ),

        "usage_type":
            clean_observable_value(
                usage_type
            ),

        "is_tor":
            normalized_is_tor,

        "last_reported_at":
            last_reported_datetime,

        "checked_at":
            datetime.utcnow(),

        "raw_response":
            raw_response,

        "id_ioc":
            id_ioc_bin,
    }

    if existing:

        db.execute(
            text(
                """
                UPDATE threat_intelligence_abuseipdb
                SET
                    abuse_confidence_score =
                        :abuse_confidence_score,
                    total_reports =
                        :total_reports,
                    num_distinct_users =
                        :num_distinct_users,
                    country_code =
                        :country_code,
                    country_name =
                        :country_name,
                    isp =
                        :isp,
                    usage_type =
                        :usage_type,
                    is_tor =
                        :is_tor,
                    last_reported_at =
                        :last_reported_at,
                    checked_at =
                        :checked_at,
                    raw_response =
                        :raw_response
                WHERE id_ioc = :id_ioc
                """
            ),
            params,
        )

    else:

        db.execute(
            text(
                """
                INSERT INTO threat_intelligence_abuseipdb
                (
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
                    checked_at,
                    raw_response
                )
                VALUES
                (
                    :id_ti_abuse,
                    :id_ioc,
                    :abuse_confidence_score,
                    :total_reports,
                    :num_distinct_users,
                    :country_code,
                    :country_name,
                    :isp,
                    :usage_type,
                    :is_tor,
                    :last_reported_at,
                    :checked_at,
                    :raw_response
                )
                """
            ),
            {
                **params,
                "id_ti_abuse":
                    uuid.uuid4().bytes,
            },
        )

    print(
        "DEBUG TI ABUSEIPDB SAVED:",
        ioc.type_ioc,
        ioc.valeur,
        flush=True,
    )

    return True


# ============================================================
# ASSOCIATION IOC <-> ENRICHISSEMENT
# ============================================================

def enrichment_matches_ioc(
    enrichment_data: Any,
    ioc: IOC,
) -> bool:

    if not enrichment_data:
        return False

    ioc_type = normalize_ioc_type(
        ioc.type_ioc
    )

    ioc_value = clean_observable_value(
        ioc.valeur
    )

    if not ioc_value:
        return False

    normalized = normalize_object(
        enrichment_data
    )

    if normalized is None:
        return False

    if isinstance(
        normalized,
        dict,
    ):

        url_queried = normalized.get(
            "url_queried"
        )

        if (
            ioc_type == "url"
            and normalize_bool(
                url_queried
            ) is True
        ):
            return True

        hash_queried = normalized.get(
            "hash_queried"
        )

        if (
            ioc_type == "hash"
            and normalize_bool(
                hash_queried
            ) is True
        ):
            return True

        ip_queried = normalized.get(
            "ip_queried"
        )

        if (
            ioc_type == "ip"
            and normalize_bool(
                ip_queried
            ) is True
        ):
            return True

    expected = ioc_value.strip().lower()

    generic_ioc_keys = {

        "ioc",
        "ioc_value",
        "iocvalue",
        "value",
        "valeur",
        "observable",
        "observable_value",
        "observablevalue",
        "indicator",
        "indicator_value",
        "indicatorvalue",
        "target",
        "target_value",
        "targetvalue",
        "query",
        "lookup",
        "resource",
        "resource_value",
        "resourcevalue",
    }

    type_keys = {

        "ip": {
            "ip",
            "ip_address",
            "ipaddress",
            "address",
            "host_ip",
            "hostip",
        },

        "url": {
            "url",
            "url_address",
            "urladdress",
            "resource_url",
            "resourceurl",
        },

        "domain": {
            "domain",
            "hostname",
            "fqdn",
            "host",
            "domain_name",
            "domainname",
        },

        "hash": {
            "hash",
            "sha256",
            "sha1",
            "md5",
            "file_hash",
            "filehash",
        },
    }

    generic_keys_normalized = {
        str(key).strip().lower()
        for key in generic_ioc_keys
    }

    explicit_type_keys = {
        str(key).strip().lower()
        for key in type_keys.get(
            ioc_type,
            set(),
        )
    }

    def exact_match(
        value: Any,
    ) -> bool:

        if value is None:
            return False

        if isinstance(
            value,
            (dict, list),
        ):
            return False

        candidate = clean_observable_value(
            value
        )

        if not candidate:
            return False

        return (
            candidate.strip().lower()
            == expected
        )

    def walk(
        data: Any,
    ) -> bool:

        if isinstance(
            data,
            dict,
        ):

            for key, value in data.items():

                key_normalized = str(
                    key
                ).strip().lower()

                if (
                    key_normalized
                    in explicit_type_keys
                ):

                    if exact_match(
                        value
                    ):
                        return True

                if (
                    key_normalized
                    in generic_keys_normalized
                ):

                    if exact_match(
                        value
                    ):
                        return True

            current_type = (

                data.get("type")

                or data.get("type_ioc")

                or data.get("ioc_type")

                or data.get("iocType")

                or data.get("kind")
            )

            if current_type is not None:

                normalized_current_type = (
                    normalize_ioc_type(
                        current_type
                    )
                )

                if (
                    normalized_current_type
                    == ioc_type
                ):

                    current_value = (

                        data.get("value")

                        or data.get("valeur")

                        or data.get("ioc")

                        or data.get("observable")

                        or data.get("indicator")

                        or data.get("url")

                        or data.get("domain")

                        or data.get("ip")

                        or data.get("hash")
                    )

                    if exact_match(
                        current_value
                    ):
                        return True

            for value in data.values():

                if isinstance(
                    value,
                    (dict, list),
                ):

                    if walk(value):
                        return True

            return False

        if isinstance(
            data,
            list,
        ):

            for item in data:

                if walk(item):
                    return True

            return False

        return False

    matched = walk(
        normalized
    )

    if not matched:

        print(
            "DEBUG TI STRICT NO MATCH:",
            ioc_type,
            ioc_value,
            flush=True,
        )

    return matched


# ============================================================
# IOC
# ============================================================

def save_ioc(
    db: Session,
    ioc_type: Any,
    value: Any,
) -> IOC | None:

    clean_value = clean_observable_value(
        value
    )

    if not clean_value:
        return None

    db_ioc_type = get_database_ioc_type(
        ioc_type,
        clean_value,
    )

    if db_ioc_type is None:

        print(
            "DEBUG IOC SKIPPED:",
            "type non supporté:",
            ioc_type,
            "value:",
            clean_value,
            flush=True,
        )

        return None

    if (
        db_ioc_type == "IP"
        and is_private_or_invalid_ip(
            clean_value
        )
    ):

        print(
            "DEBUG IOC IP SKIPPED:",
            clean_value,
            flush=True,
        )

        return None

    now = datetime.utcnow()

    existing = (
        db.query(IOC)
        .filter(
            IOC.type_ioc
            == db_ioc_type,

            IOC.valeur
            == clean_value,
        )
        .first()
    )

    if existing:

        existing.date_derniere_observation = now

        print(
            "DEBUG IOC EXISTING:",
            existing.type_ioc,
            existing.valeur,
            existing.id_ioc,
            flush=True,
        )

        return existing

    ioc = IOC(

        type_ioc=db_ioc_type,

        valeur=clean_value,

        is_ioc=True,

        date_premiere_observation=now,

        date_derniere_observation=now,
    )

    db.add(ioc)

    db.flush()

    print(
        "DEBUG IOC CREATED:",
        ioc.type_ioc,
        ioc.valeur,
        ioc.id_ioc,
        flush=True,
    )

    return ioc


# ============================================================
# EXTRACTION RAW EVENT WAZUH
# ============================================================

def extract_real_wazuh_event(
    raw_event: Any,
) -> dict | None:

    if raw_event is None:
        return None

    raw_event = normalize_object(
        raw_event
    )

    if raw_event is None:
        return None

    if isinstance(
        raw_event,
        str,
    ):

        try:

            raw_event = json.loads(
                raw_event
            )

        except Exception:

            return None

        raw_event = normalize_object(
            raw_event
        )

    if isinstance(
        raw_event,
        list,
    ):

        if len(raw_event) == 1:

            candidate = raw_event[0]

            if isinstance(
                candidate,
                dict,
            ):

                raw_event = candidate

        else:

            for item in raw_event:

                if not isinstance(
                    item,
                    dict,
                ):
                    continue

                if isinstance(
                    item.get("all_fields"),
                    dict,
                ):

                    raw_event = item[
                        "all_fields"
                    ]

                    break

                if (
                    "agent" in item
                    and "rule" in item
                ):

                    raw_event = item

                    break

    if not isinstance(
        raw_event,
        dict,
    ):

        return None

    # --------------------------------------------------------
    # all_fields
    # --------------------------------------------------------

    if isinstance(
        raw_event.get("all_fields"),
        dict,
    ):

        raw_event = raw_event[
            "all_fields"
        ]

    # --------------------------------------------------------
    # message
    # --------------------------------------------------------

    elif isinstance(
        raw_event.get("message"),
        dict,
    ):

        message_data = raw_event[
            "message"
        ]

        if isinstance(
            message_data.get("all_fields"),
            dict,
        ):

            raw_event = message_data[
                "all_fields"
            ]

        elif (
            "agent" in message_data
            and "rule" in message_data
        ):

            raw_event = message_data

    # --------------------------------------------------------
    # data
    # --------------------------------------------------------

    elif isinstance(
        raw_event.get("data"),
        dict,
    ):

        data_value = raw_event[
            "data"
        ]

        if isinstance(
            data_value.get("all_fields"),
            dict,
        ):

            raw_event = data_value[
                "all_fields"
            ]

        elif (
            "agent" in data_value
            and "rule" in data_value
        ):

            raw_event = data_value

    if not isinstance(
        raw_event,
        dict,
    ):

        return None

    if (
        "agent" not in raw_event
        or "rule" not in raw_event
    ):

        print(
            "DEBUG RAW EVENT INVALID:",
            "agent/rule manquant",
            flush=True,
        )

        return None

    return raw_event


# ============================================================
# CREATION EVENEMENT WAZUH
# ============================================================

def create_wazuh_event(
    db: Session,
    raw_event: dict,
    wazuh_event_id: str | None,
    fallback_timestamp: datetime,
) -> Evenement | None:

    if not isinstance(
        raw_event,
        dict,
    ):

        print(
            "DEBUG EVENEMENT: raw_event invalide:",
            type(raw_event),
            flush=True,
        )

        return None

    raw_agent = (
        raw_event.get("agent")
        or {}
    )

    if not isinstance(
        raw_agent,
        dict,
    ):
        raw_agent = {}

    raw_rule = (
        raw_event.get("rule")
        or {}
    )

    if not isinstance(
        raw_rule,
        dict,
    ):
        raw_rule = {}

    raw_mitre = (
        raw_rule.get("mitre")
        or raw_event.get("mitre")
        or {}
    )

    if not isinstance(
        raw_mitre,
        dict,
    ):
        raw_mitre = {}

    event_type_from_raw = (
        raw_event.get("event_type")
    )

    if event_type_from_raw is None:

        event_type_from_raw = (
            raw_event.get("attack_type")
        )

    if event_type_from_raw is None:

        event_type_from_raw = (
            raw_event.get("classification")
        )

    if event_type_from_raw is not None:

        event_type_from_raw = str(
            event_type_from_raw
        ).strip()

    raw_decoder = (
        raw_event.get("decoder")
        or {}
    )

    if not isinstance(
        raw_decoder,
        dict,
    ):
        raw_decoder = {}

    raw_data = (
        raw_event.get("data")
        or {}
    )

    if not isinstance(
        raw_data,
        dict,
    ):
        raw_data = {}

    raw_win = (
        raw_data.get("win")
        or {}
    )

    if not isinstance(
        raw_win,
        dict,
    ):
        raw_win = {}

    raw_system = (
        raw_win.get("system")
        or {}
    )

    if not isinstance(
        raw_system,
        dict,
    ):
        raw_system = {}

    raw_eventdata = (
        raw_win.get("eventdata")
        or {}
    )

    if not isinstance(
        raw_eventdata,
        dict,
    ):
        raw_eventdata = {}

    event_external_id = (
        wazuh_event_id
        or raw_event.get("id")
    )

    if event_external_id is None:

        print(
            "DEBUG EVENEMENT: aucun identifiant Wazuh",
            flush=True,
        )

        return None

    event_external_id = str(
        event_external_id
    ).strip()

    if not event_external_id:
        return None

    event_timestamp = parse_datetime(
        raw_event.get("timestamp")
        or fallback_timestamp
    )

    event_title = str(
        raw_event.get("title")
        or raw_rule.get("description")
        or "Wazuh Event"
    )

    event_description = str(
        raw_event.get("description")
        or raw_event.get("text")
        or raw_rule.get("description")
        or event_title
    )

    wazuh_level = raw_rule.get(
        "level"
    )

    try:

        if wazuh_level is not None:

            wazuh_level = int(
                wazuh_level
            )

    except Exception:

        wazuh_level = None

    rule_id = raw_rule.get(
        "id"
    )

    if rule_id is not None:
        rule_id = str(rule_id)

    decoder_name = raw_decoder.get(
        "name"
    )

    if decoder_name is not None:
        decoder_name = str(decoder_name)

    event_severity = normalize_severity(
        raw_rule.get("level")
        or raw_event.get("severity")
    )

    utilisateur_event = (
        raw_eventdata.get(
            "detection User"
        )
        or raw_eventdata.get(
            "user"
        )
        or raw_eventdata.get(
            "User"
        )
        or raw_event.get(
            "user"
        )
    )

    if utilisateur_event is not None:

        utilisateur_event = str(
            utilisateur_event
        )

    hostname_event = (
        raw_system.get(
            "computer"
        )
        or raw_event.get(
            "hostname"
        )
    )

    if hostname_event is not None:

        hostname_event = str(
            hostname_event
        )

    localisation_event = (
        raw_event.get(
            "location"
        )
    )

    if localisation_event is not None:

        localisation_event = str(
            localisation_event
        )

    # ========================================================
    # AGENT
    # ========================================================

    agent_db = None

    agent_wazuh_id = raw_agent.get(
        "id"
    )

    if agent_wazuh_id is not None:

        agent_wazuh_id = str(
            agent_wazuh_id
        ).strip()

        agent_db = (
            db.query(Agent)
            .filter(
                Agent.identifiant_externe
                == agent_wazuh_id
            )
            .first()
        )

    if agent_db is None:

        agent_name = raw_agent.get(
            "name"
        )

        if agent_name:

            agent_db = (
                db.query(Agent)
                .filter(
                    Agent.nom
                    == str(agent_name)
                )
                .first()
            )

    if agent_db is None:

        agents = (
            db.query(Agent)
            .filter(
                Agent.statut == "ACTIVE"
            )
            .all()
        )

        if len(agents) == 1:

            agent_db = agents[0]

            print(
                "DEBUG AGENT FALLBACK:",
                agent_db.identifiant_externe,
                agent_db.nom,
                "=>",
                agent_db.id_agent.hex,
                flush=True,
            )

    print(
        "DEBUG AGENT:",
        raw_agent.get("id"),
        raw_agent.get("name"),
        "=>",
        agent_db.id_agent.hex
        if agent_db
        else None,
        flush=True,
    )

    if agent_db is None:

        raise ValueError(
            "Agent Wazuh introuvable en base pour "
            f"id={raw_agent.get('id')} "
            f"name={raw_agent.get('name')}"
        )

    # ========================================================
    # DONNÉES NORMALISÉES
    # ========================================================

    normalized_data = {

        "source":
            "Wazuh",

        "event_type":
            event_type_from_raw,

        "mitre":
            raw_mitre,

        "agent": {

            "id":
                raw_agent.get("id"),

            "name":
                raw_agent.get("name"),

            "ip":
                raw_agent.get("ip"),
        },

        "rule": {

            "id":
                raw_rule.get("id"),

            "level":
                raw_rule.get("level"),

            "description":
                raw_rule.get("description"),

            "groups":
                raw_rule.get(
                    "groups",
                    [],
                ),
        },

        "decoder":
            decoder_name,

        "windows": {

            "event_id":
                raw_system.get(
                    "eventID"
                ),

            "computer":
                raw_system.get(
                    "computer"
                ),

            "provider":
                raw_system.get(
                    "providerName"
                ),

            "threat_name":
                raw_eventdata.get(
                    "threat Name"
                ),

            "category":
                raw_eventdata.get(
                    "category Name"
                ),

            "severity":
                raw_eventdata.get(
                    "severity Name"
                ),

            "detection_user":
                raw_eventdata.get(
                    "detection User"
                ),

            "action":
                raw_eventdata.get(
                    "action Name"
                ),

            "path":
                raw_eventdata.get(
                    "path"
                ),
        },
    }

    evenement = Evenement(

        id_agent=
            agent_db.id_agent,

        id_actif=
            None,

        id_source=
            None,

        identifiant_externe=
            event_external_id,

        timestamp_evenement=
            event_timestamp,

        timestamp_reception=
            datetime.utcnow(),

        type_evenement=
            "WAZUH_ALERT",

        categorie=
            event_type_from_raw,

        titre=
            event_title,

        description=
            event_description,

        severite=
            event_severity,

        niveau_wazuh=
            wazuh_level,

        rule_id_externe=
            rule_id,

        decoder=
            decoder_name,

        utilisateur=
            utilisateur_event,

        hostname=
            hostname_event,

        localisation=
            localisation_event,

        donnees_brutes=
            raw_event,

        donnees_normalisees=
            normalized_data,
    )
    
    db.add(
        evenement
    )

    db.flush()
    sync_event_mitre(
        db,
        evenement.id_evenement,
        raw_mitre,
        source_detection="Wazuh",
        confiance=100,
    )

    print(
        "DEBUG EVENEMENT CREATED:",
        evenement.id_evenement,
        "WAZUH ID:",
        evenement.identifiant_externe,
        "EVENT TYPE:",
        event_type_from_raw,
        "MITRE:",
        raw_mitre,
        flush=True,
    )

    return evenement


# ============================================================
# ENDPOINT SHUFFLE
# ============================================================

@router.post("/shuffle")
def ingest_shuffle(
    payload: dict,
    db: Session = Depends(get_db),
):

    try:

        payload = normalize_object(
            payload
        )

        if not isinstance(
            payload,
            dict,
        ):

            raise HTTPException(
                status_code=400,
                detail="Payload Shuffle invalide",
            )

        # ====================================================
        # DONNÉES PRINCIPALES
        # ====================================================

        alert_data = (
            normalize_object(
                payload.get("alert")
            )
            or {}
        )

        iocs_data = (
            normalize_object(
                payload.get("iocs")
            )
            or {}
        )

        enrichment_data = (
            normalize_object(
                payload.get("enrichment")
            )
            or {}
        )

        risk_data = (
            normalize_object(
                payload.get("risk")
            )
            or {}
        )

        observables_data = (
            normalize_object(
                payload.get("observables")
            )
            or []
        )

        thehive_data = (
            normalize_object(
                payload.get("thehive")
            )
            or {}
        )

        if not isinstance(
            alert_data,
            dict,
        ):
            alert_data = {}

        if not isinstance(
            iocs_data,
            dict,
        ):
            iocs_data = {}

        if not isinstance(
            enrichment_data,
            dict,
        ):
            enrichment_data = {}

        if not isinstance(
            risk_data,
            dict,
        ):
            risk_data = {}

        if not isinstance(
            observables_data,
            list,
        ):
            observables_data = []

        if not isinstance(
            thehive_data,
            dict,
        ):
            thehive_data = {}

        # ====================================================
        # CLASSIFICATION / MITRE
        # ====================================================

        event_type_data = normalize_object(
            payload.get("event_type")
        )

        if event_type_data is not None:

            event_type_data = str(
                event_type_data
            ).strip()

        mitre_data = normalize_object(
            payload.get("mitre")
        ) or {}

        if not isinstance(
            mitre_data,
            dict,
        ):

            mitre_data = {}

        print(
            "DEBUG EVENT TYPE:",
            event_type_data,
            flush=True,
        )

        print(
            "DEBUG MITRE:",
            mitre_data,
            flush=True,
        )

        # ====================================================
        # RAW WAZUH
        # ====================================================

        raw_event = extract_real_wazuh_event(

            payload.get("raw_event")

            or payload.get("evenement")

            or payload.get("wazuh")
        )

        print(
            "DEBUG RAW EVENT TYPE:",
            type(raw_event),
            flush=True,
        )

        if isinstance(
            raw_event,
            dict,
        ):

            print(
                "DEBUG RAW EVENT KEYS:",
                list(raw_event.keys()),
                flush=True,
            )

        now = datetime.utcnow()

        # ====================================================
        # TIMESTAMP
        # ====================================================

        timestamp_value = (

            alert_data.get(
                "timestamp"
            )

            or (
                raw_event.get("timestamp")
                if isinstance(
                    raw_event,
                    dict,
                )
                else None
            )

            or now
        )

        timestamp = parse_datetime(
            timestamp_value
        )

        # ====================================================
        # WAZUH EVENT ID
        # ====================================================

        wazuh_event_id = (

            alert_data.get(
                "wazuh_event_id"
            )

            or alert_data.get(
                "alert_id"
            )

            or alert_data.get(
                "event_id"
            )

        )

        if wazuh_event_id is None:

            source_ref_candidate = (
                alert_data.get(
                    "sourceRef"
                )
            )

            if source_ref_candidate:

                source_ref_candidate = str(
                    source_ref_candidate
                ).strip()

                if ":" in source_ref_candidate:

                    wazuh_event_id = (
                        source_ref_candidate
                        .rsplit(":", 1)[-1]
                    )

        if (
            wazuh_event_id is None
            and isinstance(
                raw_event,
                dict,
            )
        ):

            wazuh_event_id = raw_event.get(
                "id"
            )

        if wazuh_event_id is not None:

            wazuh_event_id = str(
                wazuh_event_id
            ).strip()

        # ====================================================
        # SOURCE REF
        # ====================================================

        source_ref = clean_observable_value(
            alert_data.get(
                "sourceRef"
            )
        )

        if source_ref is None and wazuh_event_id:

            source_ref = (
                "wazuh_alert:Wazuh:"
                + str(wazuh_event_id)
            )

        # ====================================================
        # ALERTE
        # ====================================================

        alert_title = (
            clean_observable_value(
                alert_data.get(
                    "title"
                )
            )
            or "Wazuh Alert"
        )

        alert_description = (
            clean_observable_value(
                alert_data.get(
                    "description"
                )
            )

            or clean_observable_value(
                alert_data.get(
                    "text"
                )
            )

            or alert_title
        )

        alert_severity = normalize_severity(
            alert_data.get(
                "severity"
            )
        )

        alerte = None

        if wazuh_event_id:

            alerte = (
                db.query(Alerte)
                .filter(
                    Alerte.identifiant_externe
                    == wazuh_event_id
                )
                .first()
            )

        if alerte is None and source_ref:

            alerte = (
                db.query(Alerte)
                .filter(
                    Alerte.identifiant_externe
                    == source_ref
                )
                .first()
            )

        if alerte is None:

            alerte = Alerte(

                identifiant_externe=
                    wazuh_event_id
                    or source_ref,

                identifiant_thehive=
                    None,

                titre=
                    alert_title,

                description=
                    alert_description,

                severite=
                    alert_severity,

                statut=
                    "NEW",

                source_alerte=
                    "DETECTION",

                date_creation=
                    now,

                date_mise_a_jour=
                    now,

                date_cloture=
                    None,
            )

            db.add(
                alerte
            )

            db.flush()

        else:

            alerte.titre = (
                alert_title
            )

            alerte.description = (
                alert_description
            )

            alerte.severite = (
                alert_severity
            )

            alerte.date_mise_a_jour = now

        # ====================================================
        # EVENEMENT
        # ====================================================

        evenement = None

        if wazuh_event_id:

            evenement = (
                db.query(Evenement)
                .filter(
                    Evenement.identifiant_externe
                    == wazuh_event_id
                )
                .order_by(
                    Evenement.timestamp_evenement.desc()
                )
                .first()
            )

        created_from_raw = False

        # ====================================================
        # EVENEMENT EXISTANT
        # ====================================================

        if evenement is not None:

            current_normalized = normalize_object(
                evenement.donnees_normalisees
            ) or {}

            if not isinstance(
                current_normalized,
                dict,
            ):

                current_normalized = {}

            if event_type_data:

                current_normalized[
                    "event_type"
                ] = event_type_data

            if mitre_data:

                current_normalized[
                    "mitre"
                ] = mitre_data

            evenement.donnees_normalisees = (
                current_normalized
            )

            if event_type_data:

                evenement.categorie = (
                    event_type_data
                )

            print(
                "DEBUG EVENEMENT CLASSIFICATION UPDATED:",
                event_type_data,
                flush=True,
            )

            print(
                "DEBUG EVENEMENT MITRE UPDATED:",
                mitre_data,
                flush=True,
            )

        # ====================================================
        # CREATION DEPUIS RAW
        # ====================================================

        if (
            evenement is None
            and isinstance(
                raw_event,
                dict,
            )
        ):

            raw_event_for_storage = dict(
                raw_event
            )

            if event_type_data:

                raw_event_for_storage[
                    "event_type"
                ] = event_type_data

            if mitre_data:

                raw_event_for_storage[
                    "mitre"
                ] = mitre_data

            evenement = create_wazuh_event(

                db=db,

                raw_event=
                    raw_event_for_storage,

                wazuh_event_id=
                    wazuh_event_id,

                fallback_timestamp=
                    timestamp,
            )

            if evenement is not None:

                created_from_raw = True

        # ====================================================
        # EVENEMENT STRUCTURÉ FALLBACK
        # ====================================================

        if evenement is None:

            structured_event = {

                "timestamp":
                    alert_data.get(
                        "timestamp"
                    ),

                "id":
                    wazuh_event_id,

                "location":
                    source_ref,

                "title":
                    alert_data.get(
                        "title"
                    ),

                "text":
                    (
                        alert_data.get(
                            "description"
                        )
                        or alert_data.get(
                            "text"
                        )
                    ),

                "event_type":
                    event_type_data,

                "mitre":
                    mitre_data,

                "agent": {

                    "id":
                        alert_data.get(
                            "agent_id"
                        ),

                    "name":
                        alert_data.get(
                            "agent_name"
                        ),

                    "ip":
                        alert_data.get(
                            "agent_ip"
                        ),
                },

                "rule": {

                    "id":
                        alert_data.get(
                            "rule_id"
                        ),

                    "level":
                        (
                            alert_data.get(
                                "wazuh_level"
                            )
                            or alert_data.get(
                                "severity"
                            )
                        ),

                    "description":
                        (
                            alert_data.get(
                                "description"
                            )
                            or alert_data.get(
                                "text"
                            )
                        ),

                    "groups":
                        alert_data.get(
                            "rule_groups",
                            [],
                        ),

                    "mitre":
                        mitre_data,
                },

                "decoder": {

                    "name":
                        alert_data.get(
                            "decoder"
                        )
                },

                "data":
                    normalize_object(
                        alert_data.get(
                            "data"
                        )
                    )
                    or {},
            }

            agent_id = (
                structured_event
                .get("agent", {})
                .get("id")
            )

            agent_name = (
                structured_event
                .get("agent", {})
                .get("name")
            )

            if agent_id or agent_name:

                evenement = create_wazuh_event(

                    db=db,

                    raw_event=
                        structured_event,

                    wazuh_event_id=
                        wazuh_event_id,

                    fallback_timestamp=
                        timestamp,
                )

                if evenement is not None:
                    created_from_raw = True

        # ====================================================
        # SYNCHRONISATION MITRE -> EVENEMENT_MITRE
        # ====================================================

        mitre_techniques_saved = []

        if evenement is not None:

            try:

                mitre_techniques_saved = (
                    sync_event_mitre(
                        db=db,
                        evenement_id=
                            evenement.id_evenement,
                        mitre_data=
                            mitre_data,
                        source_detection=
                            "Wazuh",
                        confiance=
                            100,
                    )
                )

            except Exception as exc:

                print(
                    "ERROR EVENEMENT-MITRE:",
                    repr(exc),
                    flush=True,
                )

                raise

        # ====================================================
        # IOCS
        # ====================================================

        ioc_created = 0
        ioc_existing = 0
        ioc_total = 0

        ioc_objects = []

        ioc_mapping = {

            "ip":
                iocs_data.get(
                    "ip"
                ),

            "url":
                iocs_data.get(
                    "url"
                ),

            "domain":
                iocs_data.get(
                    "domain"
                ),

            "hash":
                iocs_data.get(
                    "hash"
                ),

            "file_path":
                iocs_data.get(
                    "file_path"
                ),

            "command":
                iocs_data.get(
                    "command"
                ),
        }

        # ====================================================
        # OBSERVABLES SHUFFLE
        # ====================================================

        for observable in observables_data:

            if not isinstance(
                observable,
                dict,
            ):
                continue

            observable_type = (

                observable.get("type")

                or observable.get(
                    "type_ioc"
                )

                or observable.get(
                    "kind"
                )

                or observable.get(
                    "dataType"
                )
            )

            observable_value = (

                observable.get("value")

                or observable.get(
                    "valeur"
                )

                or observable.get(
                    "data"
                )
            )

            normalized_type = normalize_ioc_type(
                observable_type
            )

            if normalized_type not in {
                "ip",
                "url",
                "domain",
                "hash",
                "file_path",
                "command",
            }:
                continue

            existing_value = ioc_mapping.get(
                normalized_type
            )

            if not existing_value:

                ioc_mapping[
                    normalized_type
                ] = observable_value

            elif isinstance(
                existing_value,
                list,
            ):

                if isinstance(
                    observable_value,
                    list,
                ):

                    existing_value.extend(
                        observable_value
                    )

                else:

                    existing_value.append(
                        observable_value
                    )

            else:

                if isinstance(
                    observable_value,
                    list,
                ):

                    ioc_mapping[
                        normalized_type
                    ] = [
                        existing_value,
                        *observable_value,
                    ]

                else:

                    ioc_mapping[
                        normalized_type
                    ] = [
                        existing_value,
                        observable_value,
                    ]

        # ====================================================
        # SAUVEGARDE IOC
        # ====================================================

        for ioc_type, ioc_value in (
            ioc_mapping.items()
        ):

            if ioc_type == "command":

                print(
                    "DEBUG IOC CONTEXT ONLY:",
                    "command",
                    ioc_value,
                    flush=True,
                )

                continue

            if ioc_value is None:
                continue

            values = (

                ioc_value

                if isinstance(
                    ioc_value,
                    list,
                )

                else [
                    ioc_value
                ]
            )

            seen_values = set()

            for value in values:

                clean_value = (
                    clean_observable_value(
                        value
                    )
                )

                if not clean_value:
                    continue

                dedup_key = (
                    normalize_ioc_type(
                        ioc_type
                    ),
                    clean_value.lower(),
                )

                if dedup_key in seen_values:
                    continue

                seen_values.add(
                    dedup_key
                )

                db_ioc_type = (
                    get_database_ioc_type(
                        ioc_type,
                        clean_value,
                    )
                )

                if db_ioc_type is None:

                    print(
                        "DEBUG IOC INVALID TYPE:",
                        ioc_type,
                        clean_value,
                        flush=True,
                    )

                    continue

                if (
                    db_ioc_type == "IP"
                    and is_private_or_invalid_ip(
                        clean_value
                    )
                ):

                    print(
                        "DEBUG IOC IP SKIPPED:",
                        clean_value,
                        flush=True,
                    )

                    continue

                ioc_total += 1

                existing_ioc = (
                    db.query(IOC)
                    .filter(
                        IOC.type_ioc
                        == db_ioc_type,

                        IOC.valeur
                        == clean_value,
                    )
                    .first()
                )

                if existing_ioc:

                    existing_ioc.date_derniere_observation = (
                        now
                    )

                    ioc_existing += 1

                    ioc_db = existing_ioc

                    print(
                        "DEBUG IOC EXISTING:",
                        db_ioc_type,
                        clean_value,
                        ioc_db.id_ioc,
                        flush=True,
                    )

                else:

                    ioc_db = save_ioc(

                        db=db,

                        ioc_type=
                            ioc_type,

                        value=
                            clean_value,
                    )

                    if ioc_db:
                        ioc_created += 1

                if not ioc_db:
                    continue

                if ioc_db not in ioc_objects:

                    ioc_objects.append(
                        ioc_db
                    )

                # =================================================
                # RELATION EVENEMENT <-> IOC
                # =================================================

                if evenement:

                    id_evenement_bin = (
                        uuid_to_bytes(
                            evenement.id_evenement
                        )
                    )

                    id_ioc_bin = (
                        uuid_to_bytes(
                            ioc_db.id_ioc
                        )
                    )

                    if (
                        not id_evenement_bin
                        or not id_ioc_bin
                    ):

                        print(
                            "ERROR EVENEMENT-IOC:",
                            "UUID invalide",
                            flush=True,
                        )

                        continue

                    existing_ioc_relation = (
                        db.execute(
                            text(
                                """
                                SELECT 1
                                FROM evenement_ioc
                                WHERE id_evenement =
                                      :id_evenement
                                  AND id_ioc =
                                      :id_ioc
                                LIMIT 1
                                """
                            ),
                            {
                                "id_evenement":
                                    id_evenement_bin,

                                "id_ioc":
                                    id_ioc_bin,
                            },
                        ).first()
                    )

                    if existing_ioc_relation is None:

                        db.execute(
                            text(
                                """
                                INSERT INTO evenement_ioc
                                (
                                    id_evenement,
                                    id_ioc,
                                    role_ioc,
                                    contexte
                                )
                                VALUES
                                (
                                    :id_evenement,
                                    :id_ioc,
                                    :role_ioc,
                                    :contexte
                                )
                                """
                            ),
                            {
                                "id_evenement":
                                    id_evenement_bin,

                                "id_ioc":
                                    id_ioc_bin,

                                "role_ioc":
                                    normalize_ioc_type(
                                        db_ioc_type
                                    ),

                                "contexte":
                                    "IOC extrait depuis Shuffle/Wazuh",
                            },
                        )

                        print(
                            "DEBUG EVENEMENT-IOC CREATED:",
                            evenement.id_evenement,
                            ioc_db.id_ioc,
                            db_ioc_type,
                            clean_value,
                            flush=True,
                        )

        # ====================================================
        # ENRICHISSEMENT
        # ====================================================

        enrichment_received = bool(
            enrichment_data
        )

        virustotal_data = (
            enrichment_data.get(
                "virustotal"
            )
        )

        abuseipdb_data = (
            enrichment_data.get(
                "abuseipdb"
            )
        )

        ti_virustotal_saved = 0
        ti_abuseipdb_saved = 0

        # ====================================================
        # THREAT INTELLIGENCE
        # ====================================================

        for ioc_db in ioc_objects:

            ioc_type = normalize_ioc_type(
                ioc_db.type_ioc
            )

            # ------------------------------------------------
            # VirusTotal
            # ------------------------------------------------

            if (
                virustotal_data
                and ioc_type in {
                    "url",
                    "domain",
                    "hash",
                    "ip",
                }
            ):

                try:

                    if (
                        ioc_type == "ip"
                        and is_private_or_invalid_ip(
                            ioc_db.valeur
                        )
                    ):

                        print(
                            "DEBUG TI VIRUSTOTAL IP SKIPPED:",
                            ioc_db.valeur,
                            flush=True,
                        )

                    elif enrichment_matches_ioc(
                        virustotal_data,
                        ioc_db,
                    ):

                        saved = (
                            save_virustotal_intelligence(
                                db=db,
                                ioc=ioc_db,
                                virustotal_data=
                                    virustotal_data,
                            )
                        )

                        if saved:
                            ti_virustotal_saved += 1

                    else:

                        print(
                            "DEBUG TI VIRUSTOTAL NOT ASSOCIATED:",
                            ioc_type,
                            ioc_db.valeur,
                            flush=True,
                        )

                except Exception as exc:

                    print(
                        "ERROR TI VIRUSTOTAL:",
                        repr(exc),
                        flush=True,
                    )

            # ------------------------------------------------
            # AbuseIPDB
            # ------------------------------------------------

            if (
                abuseipdb_data
                and ioc_type == "ip"
            ):

                try:

                    if is_private_or_invalid_ip(
                        ioc_db.valeur
                    ):

                        print(
                            "DEBUG TI ABUSEIPDB IP SKIPPED:",
                            ioc_db.valeur,
                            flush=True,
                        )

                    elif enrichment_matches_ioc(
                        abuseipdb_data,
                        ioc_db,
                    ):

                        saved = (
                            save_abuseipdb_intelligence(
                                db=db,
                                ioc=ioc_db,
                                abuseipdb_data=
                                    abuseipdb_data,
                            )
                        )

                        if saved:
                            ti_abuseipdb_saved += 1

                    else:

                        print(
                            "DEBUG TI ABUSEIPDB NOT ASSOCIATED:",
                            ioc_type,
                            ioc_db.valeur,
                            flush=True,
                        )

                except Exception as exc:

                    print(
                        "ERROR TI ABUSEIPDB:",
                        repr(exc),
                        flush=True,
                    )

        # ====================================================
        # RISQUE
        # ====================================================

        risk_score = risk_data.get(
            "score"
        )

        try:

            risk_score = int(
                risk_score
            )

        except Exception:

            risk_score = 0

        risk_level = normalize_severity(
            risk_data.get(
                "level"
            )
        )

        risk_action = (
            clean_observable_value(
                risk_data.get(
                    "action"
                )
            )
            or "MONITOR"
        )

        risk_reason = (
            clean_observable_value(
                risk_data.get(
                    "reason"
                )
            )
        )

        force_case = normalize_bool(
            risk_data.get(
                "force_case"
            )
        )

        if force_case is None:
            force_case = False

        # ====================================================
        # EVALUATION RISQUE
        # ====================================================

        evaluation = (
            db.query(
                EvaluationRisque
            )
            .filter(
                EvaluationRisque.id_alerte
                == alerte.id_alerte
            )
            .order_by(
                EvaluationRisque.date_calcul.desc()
            )
            .first()
        )

        if evaluation is None:

            evaluation = EvaluationRisque(

                id_evenement=None,

                id_alerte=
                    alerte.id_alerte,

                score_risque=
                    risk_score,

                niveau_risque=
                    risk_level,

                action_recommandee=
                    risk_action,

                raison=
                    risk_reason,

                force_case=
                    force_case,

                date_calcul=
                    now,
            )

            db.add(
                evaluation
            )

        else:

            evaluation.id_evenement = None

            evaluation.id_alerte = (
                alerte.id_alerte
            )

            evaluation.score_risque = (
                risk_score
            )

            evaluation.niveau_risque = (
                risk_level
            )

            evaluation.action_recommandee = (
                risk_action
            )

            evaluation.raison = (
                risk_reason
            )

            evaluation.force_case = (
                force_case
            )

            evaluation.date_calcul = (
                now
            )

        db.flush()

        # ====================================================
        # RELATION ALERTE <-> EVENEMENT
        # ====================================================

        if evenement:

            id_alerte_bin = (
                uuid_to_bytes(
                    alerte.id_alerte
                )
            )

            id_evenement_bin = (
                uuid_to_bytes(
                    evenement.id_evenement
                )
            )

            if (
                id_alerte_bin
                and id_evenement_bin
            ):

                existing_relation = (
                    db.execute(
                        text(
                            """
                            SELECT 1
                            FROM alerte_evenement
                            WHERE id_alerte =
                                  :id_alerte
                              AND id_evenement =
                                  :id_evenement
                            LIMIT 1
                            """
                        ),
                        {
                            "id_alerte":
                                id_alerte_bin,

                            "id_evenement":
                                id_evenement_bin,
                        },
                    ).first()
                )

                if existing_relation is None:

                    db.execute(
                        text(
                            """
                            INSERT INTO alerte_evenement
                            (
                                id_alerte,
                                id_evenement,
                                role_evenement
                            )
                            VALUES
                            (
                                :id_alerte,
                                :id_evenement,
                                :role_evenement
                            )
                            """
                        ),
                        {
                            "id_alerte":
                                id_alerte_bin,

                            "id_evenement":
                                id_evenement_bin,

                            "role_evenement":
                                "SOURCE",
                        },
                    )

                    print(
                        "DEBUG ALERTE-EVENEMENT CREATED:",
                        alerte.id_alerte,
                        evenement.id_evenement,
                        flush=True,
                    )

        # ====================================================
        # INCIDENT
        # ====================================================

        incident = None

        should_create_case = (

            str(
                risk_action
            ).upper()
            == "CREATE_CASE"

            or force_case
        )

        if should_create_case:

            incident = (
                db.query(
                    Incident
                )
                .filter(
                    Incident.id_alerte
                    == alerte.id_alerte
                )
                .first()
            )

            if incident is None:

                incident = Incident(

                    id_alerte=
                        alerte.id_alerte,

                    id_actif=
                        None,

                    id_utilisateur_createur=
                        None,

                    id_utilisateur_assigne=
                        None,

                    identifiant_thehive=
                        None,

                    titre=
                        alert_title,

                    description=
                        alert_description,

                    severite=
                        risk_level,

                    priorite=
                        risk_level,

                    statut=
                        "OPEN",

                    date_creation=
                        now,

                    date_mise_a_jour=
                        now,

                    date_cloture=
                        None,
                )

                db.add(
                    incident
                )

                db.flush()

            else:

                incident.titre = (
                    alert_title
                )

                incident.description = (
                    alert_description
                )

                incident.severite = (
                    risk_level
                )

                incident.priorite = (
                    risk_level
                )

                incident.date_mise_a_jour = (
                    now
                )

        # ====================================================
        # THEHIVE
        # ====================================================

        if isinstance(
            thehive_data,
            dict,
        ):

            thehive_case_id = (

                thehive_data.get(
                    "case_id"
                )

                or thehive_data.get(
                    "thehive_case_id"
                )

                or thehive_data.get(
                    "identifiant_thehive"
                )

                or thehive_data.get(
                    "id"
                )
            )

            if thehive_case_id:

                thehive_case_id = str(
                    thehive_case_id
                )

                alerte.identifiant_thehive = (
                    thehive_case_id
                )

                alerte.date_mise_a_jour = now

                if incident:

                    incident.identifiant_thehive = (
                        thehive_case_id
                    )

                    incident.date_mise_a_jour = now

        # ====================================================
        # COMMIT
        # ====================================================

        db.commit()

        # ====================================================
        # RESPONSE
        # ====================================================

        return {

            "status":
                "stored",

            "source":
                "Shuffle",

            "source_ref":
                source_ref,

            "classification": {

                "event_type":
                    event_type_data,

                "mitre":
                    mitre_data,

                "techniques_saved":
                    mitre_techniques_saved,
            },

            "alerte": {

                "id_alerte":
                    str(
                        alerte.id_alerte
                    ),

                "identifiant_externe":
                    alerte.identifiant_externe,

                "titre":
                    alerte.titre,

                "severite":
                    alerte.severite,

                "statut":
                    alerte.statut,
            },

            "evenement": {

                "found":
                    evenement is not None,

                "created_from_raw":
                    created_from_raw,

                "id_evenement":
                    (
                        str(
                            evenement.id_evenement
                        )
                        if evenement
                        else None
                    ),

                "identifiant_externe":
                    (
                        evenement.identifiant_externe
                        if evenement
                        else None
                    ),

                "wazuh_event_id":
                    wazuh_event_id,

                "mitre_techniques":
                    mitre_techniques_saved,
            },

            "iocs": {

                "created":
                    ioc_created,

                "existing":
                    ioc_existing,

                "total":
                    ioc_total,
            },

            "enrichment": {

                "received":
                    enrichment_received,

                "virustotal":
                    virustotal_data is not None,

                "abuseipdb":
                    abuseipdb_data is not None,

                "virustotal_saved":
                    ti_virustotal_saved,

                "abuseipdb_saved":
                    ti_abuseipdb_saved,
            },

            "evaluation_risque": {

                "id_evaluation":
                    str(
                        evaluation.id_evaluation
                    ),

                "score":
                    evaluation.score_risque,

                "niveau":
                    evaluation.niveau_risque,

                "action":
                    evaluation.action_recommandee,

                "force_case":
                    evaluation.force_case,

                "id_evenement":
                    (
                        str(
                            evaluation.id_evenement
                        )
                        if evaluation.id_evenement
                        else None
                    ),

                "id_alerte":
                    (
                        str(
                            evaluation.id_alerte
                        )
                        if evaluation.id_alerte
                        else None
                    ),
            },

            "incident": {

                "created":
                    incident is not None,

                "id_incident":
                    (
                        str(
                            incident.id_incident
                        )
                        if incident
                        else None
                    ),

                "identifiant_thehive":
                    (
                        incident.identifiant_thehive
                        if incident
                        else None
                    ),
            },
        }

    except HTTPException:

        db.rollback()
        raise

    except Exception as exc:

        db.rollback()

        print(
            "ERROR SHUFFLE INGEST:",
            repr(exc),
            flush=True,
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )


# ============================================================
# CALLBACK THEHIVE
# ============================================================

@router.post("/shuffle/thehive")
def update_shuffle_thehive(

    payload: dict,

    db: Session = Depends(get_db),

):

    try:

        payload = normalize_object(
            payload
        )

        print(
            "DEBUG THEHIVE CALLBACK PAYLOAD:",
            payload,
            flush=True,
        )

        if not isinstance(
            payload,
            dict,
        ):

            raise HTTPException(
                status_code=400,
                detail="Payload TheHive invalide",
            )

        wazuh_event_id = (

            payload.get(
                "wazuh_event_id"
            )

            or payload.get(
                "alert_id"
            )

            or payload.get(
                "sourceRef"
            )
        )

        thehive_case_id = (

            payload.get(
                "thehive_case_id"
            )

            or payload.get(
                "case_id"
            )

            or payload.get(
                "identifiant_thehive"
            )

        )

        if not wazuh_event_id:

            raise HTTPException(
                status_code=400,
                detail="wazuh_event_id manquant",
            )

        if not thehive_case_id:

            raise HTTPException(
                status_code=400,
                detail="thehive_case_id manquant",
            )

        wazuh_event_id = str(
            wazuh_event_id
        ).strip()

        # ----------------------------------------------------
        # Si Shuffle renvoie sourceRef complet :
        #
        # wazuh_alert:Wazuh:1790005420.3218938
        #
        # on extrait uniquement l'ID Wazuh.
        # ----------------------------------------------------

        if ":" in wazuh_event_id:

            possible_id = (
                wazuh_event_id
                .rsplit(":", 1)[-1]
                .strip()
            )

            if possible_id:

                wazuh_event_id = possible_id

        thehive_case_id = str(
            thehive_case_id
        ).strip()

        alerte = (

            db.query(Alerte)

            .filter(
                Alerte.identifiant_externe
                == wazuh_event_id
            )

            .first()
        )

        # ----------------------------------------------------
        # Fallback avec sourceRef
        # ----------------------------------------------------

        if alerte is None:

            source_ref = (
                "wazuh_alert:Wazuh:"
                + wazuh_event_id
            )

            alerte = (

                db.query(Alerte)

                .filter(
                    Alerte.identifiant_externe
                    == source_ref
                )

                .first()
            )

        if alerte is None:

            raise HTTPException(
                status_code=404,
                detail=(
                    "Alerte introuvable pour "
                    f"{wazuh_event_id}"
                ),
            )

        alerte.identifiant_thehive = (
            thehive_case_id
        )

        alerte.date_mise_a_jour = (
            datetime.utcnow()
        )

        incident = (

            db.query(Incident)

            .filter(
                Incident.id_alerte
                == alerte.id_alerte
            )

            .first()
        )

        if incident:

            incident.identifiant_thehive = (
                thehive_case_id
            )

            incident.date_mise_a_jour = (
                datetime.utcnow()
            )

        db.commit()

        return {

            "status":
                "updated",

            "alerte": {

                "id_alerte":
                    str(
                        alerte.id_alerte
                    ),

                "identifiant_externe":
                    alerte.identifiant_externe,

                "identifiant_thehive":
                    alerte.identifiant_thehive,
            },

            "incident": {

                "updated":
                    incident is not None,

                "id_incident":
                    (
                        str(
                            incident.id_incident
                        )
                        if incident
                        else None
                    ),

                "identifiant_thehive":
                    (
                        incident.identifiant_thehive
                        if incident
                        else None
                    ),
            },
        }

    except HTTPException:

        db.rollback()
        raise

    except Exception as exc:

        db.rollback()

        print(
            "ERROR THEHIVE CALLBACK:",
            repr(exc),
            flush=True,
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )