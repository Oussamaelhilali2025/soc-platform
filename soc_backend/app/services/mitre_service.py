import json
import re
import uuid
from typing import Any

from sqlalchemy import MetaData, Table, delete, select


metadata = MetaData()
_tables = {}


def get_table(db, name: str):
    """
    Charge la structure réelle d'une table existante.

    Aucun nouveau schéma SQL n'est créé.
    Les tables existantes de MariaDB sont utilisées telles quelles.
    """

    if name not in _tables:
        _tables[name] = Table(
            name,
            metadata,
            autoload_with=db.bind,
        )

    return _tables[name]


def uuid_to_bytes(value):
    """
    Convertit un UUID Python / chaîne UUID / bytes
    vers le format BINARY(16) utilisé par MariaDB.
    """

    if value is None:
        return None

    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    if isinstance(value, uuid.UUID):
        return value.bytes

    if isinstance(value, str):
        value = value.strip()

        if not value:
            return None

        try:
            return uuid.UUID(value).bytes
        except ValueError:
            return value.encode()

    return value


def normalize_mitre_value(value: Any):
    """
    Transforme une valeur JSON ou une chaîne JSON
    en structure Python exploitable.
    """

    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return value

    if isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        try:
            return json.loads(text)
        except Exception:
            return text

    return value


MITRE_TECHNIQUE_PATTERN = re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    re.IGNORECASE,
)


def is_mitre_technique_id(value: str) -> bool:
    """
    Vérifie si une valeur correspond à un identifiant
    de technique MITRE ATT&CK.

    Exemples :
        T1070
        T1070.004
        T1485
    """

    if not value:
        return False

    return bool(
        MITRE_TECHNIQUE_PATTERN.match(
            value.strip()
        )
    )


def to_string_list(value: Any) -> list[str]:
    """
    Convertit différentes formes de données MITRE
    en liste de chaînes.
    """

    value = normalize_mitre_value(value)

    if value is None:
        return []

    # Exemple :
    # ["T1070.004", "T1485"]
    if isinstance(value, list):

        result = []

        for item in value:

            if isinstance(item, dict):

                candidate = (
                    item.get("id")
                    or item.get("technique_id")
                    or item.get("name")
                    or item.get("technique")
                )

                if candidate is not None:
                    result.append(
                        str(candidate).strip()
                    )

            elif item is not None:

                text = str(item).strip()

                if text:
                    result.append(text)

        return list(
            dict.fromkeys(result)
        )

    # Exemple :
    # {"id": "T1070.004"}
    if isinstance(value, dict):

        candidate = (
            value.get("id")
            or value.get("technique_id")
            or value.get("name")
            or value.get("technique")
        )

        if candidate is None:
            return []

        return [
            str(candidate).strip()
        ]

    text = str(value).strip()

    if not text:
        return []

    # Exemple :
    # "File Deletion, Data Destruction"
    if "," in text:

        return [
            item.strip()
            for item in text.split(",")
            if item.strip()
        ]

    return [text]


def extract_mitre_techniques(
    mitre: Any,
) -> list[str]:
    """
    Extrait les identifiants ou noms de techniques
    depuis le bloc MITRE fourni par Wazuh/Shuffle.
    """

    mitre = normalize_mitre_value(mitre)

    if not mitre:
        return []

    if isinstance(mitre, dict):

        candidates = []

        for key in (
            "id",
            "ids",
            "technique_id",
            "technique_ids",
            "techniques_ids",
            "technique",
            "techniques",
            "technique_name",
            "technique_names",
        ):

            if key in mitre:

                candidates.extend(
                    to_string_list(
                        mitre.get(key)
                    )
                )

        return list(
            dict.fromkeys(
                item.strip()
                for item in candidates
                if item
                and item.strip()
            )
        )

    return to_string_list(mitre)


def resolve_technique_ids(
    db,
    values: list[str],
) -> list[str]:
    """
    Résout les valeurs reçues vers les vrais
    id_technique présents dans technique_mitre.

    Les valeurs peuvent être :

        T1070.004

    ou :

        File Deletion
    """

    technique_table = get_table(
        db,
        "technique_mitre",
    )

    resolved = []

    for value in values:

        value = str(value).strip()

        if not value:
            continue

        # -------------------------------------------------
        # Cas 1 : valeur = identifiant MITRE
        # Exemple : T1070.004
        # -------------------------------------------------

        if is_mitre_technique_id(value):

            row = db.execute(
                select(
                    technique_table.c.id_technique
                ).where(
                    technique_table.c.id_technique
                    == value
                )
            ).first()

            if row:

                resolved.append(
                    row.id_technique
                )

            continue

        # -------------------------------------------------
        # Cas 2 : recherche exacte par nom
        # Exemple : File Deletion
        # -------------------------------------------------

        row = db.execute(
            select(
                technique_table.c.id_technique
            ).where(
                technique_table.c.nom == value
            )
        ).first()

        if row:

            resolved.append(
                row.id_technique
            )

            continue

        # -------------------------------------------------
        # Cas 3 : recherche insensible à la casse
        # -------------------------------------------------

        rows = db.execute(
            select(
                technique_table.c.id_technique,
                technique_table.c.nom,
            )
        ).all()

        value_lower = value.lower()

        for candidate in rows:

            if (
                candidate.nom
                and str(candidate.nom)
                .strip()
                .lower()
                == value_lower
            ):

                resolved.append(
                    candidate.id_technique
                )

                break

    return list(
        dict.fromkeys(resolved)
    )


def sync_event_mitre(
    db,
    evenement_id,
    mitre_data: Any,
    source_detection: str = "Wazuh",
    confiance: int = 100,
):
    """
    Synchronise le MITRE ATT&CK d'un événement
    dans evenement_mitre.

    Les anciennes relations MITRE de l'événement
    sont supprimées avant la nouvelle synchronisation.

    Cette fonction ne crée aucune table.
    """

    if not evenement_id:
        return []

    evenement_id = uuid_to_bytes(
        evenement_id
    )

    evenement_mitre_table = get_table(
        db,
        "evenement_mitre",
    )

    # -------------------------------------------------
    # Supprimer les anciennes relations MITRE
    # -------------------------------------------------

    db.execute(
        delete(
            evenement_mitre_table
        ).where(
            evenement_mitre_table.c.id_evenement
            == evenement_id
        )
    )

    # -------------------------------------------------
    # Normaliser les données MITRE
    # -------------------------------------------------

    mitre_data = normalize_mitre_value(
        mitre_data
    )

    if not mitre_data:
        return []

    # -------------------------------------------------
    # Extraire les techniques
    # -------------------------------------------------

    raw_values = extract_mitre_techniques(
        mitre_data
    )

    if not raw_values:
        return []

    # -------------------------------------------------
    # Résoudre les IDs réels
    # -------------------------------------------------

    technique_ids = resolve_technique_ids(
        db,
        raw_values,
    )

    if not technique_ids:
        return []

    # -------------------------------------------------
    # Insérer dans evenement_mitre
    # -------------------------------------------------

    inserted = []

    for technique_id in technique_ids:

        db.execute(
            evenement_mitre_table.insert().values(
                id_evenement=evenement_id,
                id_technique=technique_id,
                source_detection=source_detection,
                confiance=confiance,
            )
        )

        inserted.append(
            technique_id
        )

    return inserted


def get_alert_mitre(
    db,
    alert_id,
):
    """
    Récupère le MITRE ATT&CK d'une alerte
    uniquement depuis les relations SQL.

    Chaîne utilisée :

        alerte
          ↓
        alerte_evenement
          ↓
        evenement_mitre
          ↓
        technique_mitre
          ↓
        technique_tactique
          ↓
        tactique_mitre

    Aucun MITRE provenant de donnees_normalisees,
    Wazuh ou OWASP n'est utilisé ici.
    """

    if not alert_id:
        return {
            "techniques": [],
            "tactics": [],
        }

    alert_id = uuid_to_bytes(
        alert_id
    )

    # -------------------------------------------------
    # Charger les tables existantes
    # -------------------------------------------------

    alerte_evenement = get_table(
        db,
        "alerte_evenement",
    )

    evenement_mitre = get_table(
        db,
        "evenement_mitre",
    )

    technique_mitre = get_table(
        db,
        "technique_mitre",
    )

    technique_tactique = get_table(
        db,
        "technique_tactique",
    )

    tactique_mitre = get_table(
        db,
        "tactique_mitre",
    )

    # -------------------------------------------------
    # Construire la requête
    # -------------------------------------------------

    query = (
        select(

            # Événement MITRE
            evenement_mitre.c.id_evenement,
            evenement_mitre.c.id_technique,
            evenement_mitre.c.source_detection,
            evenement_mitre.c.confiance,

            # Technique MITRE
            technique_mitre.c.nom.label(
                "technique_nom"
            ),
            technique_mitre.c.description.label(
                "technique_description"
            ),
            technique_mitre.c.url.label(
                "technique_url"
            ),

            # Tactique MITRE
            tactique_mitre.c.id_tactique,
            tactique_mitre.c.nom.label(
                "tactique_nom"
            ),
            tactique_mitre.c.description.label(
                "tactique_description"
            ),
        )

        .select_from(

            alerte_evenement

            .join(
                evenement_mitre,
                alerte_evenement.c.id_evenement
                == evenement_mitre.c.id_evenement,
            )

            .join(
                technique_mitre,
                evenement_mitre.c.id_technique
                == technique_mitre.c.id_technique,
            )

            .outerjoin(
                technique_tactique,
                technique_mitre.c.id_technique
                == technique_tactique.c.id_technique,
            )

            .outerjoin(
                tactique_mitre,
                technique_tactique.c.id_tactique
                == tactique_mitre.c.id_tactique,
            )
        )

        .where(
            alerte_evenement.c.id_alerte
            == alert_id
        )
    )

    rows = db.execute(
        query
    ).all()

    # -------------------------------------------------
    # Construire les résultats
    # -------------------------------------------------

    techniques_map = {}
    tactics_map = {}

    for row in rows:

        technique_id = row.id_technique

        # -------------------------------------------------
        # Créer la technique si elle n'existe pas
        # -------------------------------------------------

        if technique_id not in techniques_map:

            techniques_map[technique_id] = {
                "id": technique_id,
                "name": row.technique_nom,
                "description": row.technique_description,
                "url": row.technique_url,
                "tactics": [],
                "source_detection": row.source_detection,
                "confidence": row.confiance,
            }

        # -------------------------------------------------
        # Ajouter les tactiques de la technique
        # -------------------------------------------------

        if row.id_tactique:

            tactic_id = row.id_tactique

            tactic = {
                "id": tactic_id,
                "name": row.tactique_nom,
                "description": row.tactique_description,
            }

            existing_tactic_ids = {
                item["id"]
                for item in techniques_map[
                    technique_id
                ]["tactics"]
            }

            if tactic_id not in existing_tactic_ids:

                techniques_map[
                    technique_id
                ]["tactics"].append(
                    tactic
                )

            # -------------------------------------------------
            # Ajouter la tactique à la liste globale
            # -------------------------------------------------

            if tactic_id not in tactics_map:

                tactics_map[tactic_id] = tactic

    # -------------------------------------------------
    # Résultat final
    # -------------------------------------------------

    return {
        "techniques": list(
            techniques_map.values()
        ),
        "tactics": list(
            tactics_map.values()
        ),
    }