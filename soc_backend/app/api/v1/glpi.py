import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.services.glpi import GLPIService


router = APIRouter(
    prefix="/glpi",
    tags=["GLPI"],
)


# ============================================================
# SCHEMAS
# ============================================================

class GLPITicketRequest(BaseModel):
    name: str
    content: str
    urgency: int = 3
    id_resultat: str | None = None


# ============================================================
# UTILITAIRES UUID
# ============================================================

def uuid_to_string(value):
    """
    Convertit une valeur UUID provenant de MariaDB/SQLAlchemy
    en chaîne UUID standard.
    """
    if value is None:
        return None

    if isinstance(value, uuid.UUID):
        return str(value)

    if isinstance(value, bytes):
        return str(uuid.UUID(bytes=value))

    return str(value)


def uuid_to_db_value(value):
    """
    Convertit une valeur UUID en BINARY(16) pour MariaDB.
    """
    if value is None:
        return None

    if isinstance(value, uuid.UUID):
        return value.bytes

    if isinstance(value, bytes):
        return value

    return uuid.UUID(str(value)).bytes


# ============================================================
# POST /glpi/tickets
# Création d'un ticket GLPI
# ============================================================

@router.post("/tickets")
async def create_glpi_ticket(
    request: GLPITicketRequest,
    db: Session = Depends(get_db),
):
    id_vulnerabilite = None
    id_actif = None
    id_utilisateur_createur = None

    try:

        # ========================================================
        # 1. Récupérer l'utilisateur créateur
        # ========================================================

        user_query = text(
            """
            SELECT id_utilisateur
            FROM utilisateur
            ORDER BY nom, prenom
            LIMIT 1
            """
        )

        user_row = db.execute(
            user_query
        ).mappings().first()

        if not user_row:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Aucun utilisateur disponible dans la table "
                    "utilisateur."
                ),
            )

        id_utilisateur_createur = user_row[
            "id_utilisateur"
        ]

        # ========================================================
        # 2. Récupérer vulnérabilité + actif
        # ========================================================

        if request.id_resultat:

            try:
                resultat_id = uuid.UUID(
                    request.id_resultat
                )

            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="id_resultat invalide.",
                )

            query = text(
                """
                SELECT
                    id_vulnerabilite,
                    id_actif
                FROM resultat_vulnerabilite
                WHERE id_resultat = :id_resultat
                """
            )

            row = db.execute(
                query,
                {
                    "id_resultat": resultat_id.bytes,
                },
            ).mappings().first()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail=(
                        "Résultat de vulnérabilité introuvable : "
                        f"{request.id_resultat}"
                    ),
                )

            id_vulnerabilite = row[
                "id_vulnerabilite"
            ]

            id_actif = row[
                "id_actif"
            ]

        # ========================================================
        # 3. Créer le ticket dans GLPI
        # ========================================================

        service = GLPIService()

        glpi_result = await service.create_ticket(
            name=request.name,
            content=request.content,
            urgency=request.urgency,
        )

        glpi_ticket_id = glpi_result.get("id")

        if not glpi_ticket_id:
            raise RuntimeError(
                "GLPI n'a pas retourné l'identifiant du ticket."
            )

        # ========================================================
        # 4. Déterminer la priorité SOC
        # ========================================================

        if request.urgency >= 4:
            priorite = "HIGH"

        elif request.urgency >= 3:
            priorite = "MEDIUM"

        else:
            priorite = "LOW"

        # ========================================================
        # 5. Statut initial
        # ========================================================

        statut = "OPEN"

        now = datetime.now()

        # ========================================================
        # 6. Insérer dans ticket_glpi
        # ========================================================

        insert_query = text(
            """
            INSERT INTO ticket_glpi (
                id_ticket,
                id_incident,
                id_vulnerabilite,
                id_actif,
                id_utilisateur_createur,
                identificateur_externe_glpi,
                titre,
                description,
                priorite,
                statut,
                date_creation,
                date_mise_a_jour,
                date_cloture
            )
            VALUES (
                :id_ticket,
                NULL,
                :id_vulnerabilite,
                :id_actif,
                :id_utilisateur_createur,
                :identificateur_externe_glpi,
                :titre,
                :description,
                :priorite,
                :statut,
                :date_creation,
                :date_mise_a_jour,
                NULL
            )
            """
        )

        db.execute(
            insert_query,
            {
                "id_ticket": uuid.uuid4().bytes,

                "id_vulnerabilite": (
                    uuid_to_db_value(id_vulnerabilite)
                    if id_vulnerabilite is not None
                    else None
                ),

                "id_actif": (
                    uuid_to_db_value(id_actif)
                    if id_actif is not None
                    else None
                ),

                "id_utilisateur_createur": (
                    uuid_to_db_value(
                        id_utilisateur_createur
                    )
                ),

                "identificateur_externe_glpi": str(
                    glpi_ticket_id
                ),

                "titre": request.name,

                "description": request.content,

                "priorite": priorite,

                "statut": statut,

                "date_creation": now,

                "date_mise_a_jour": now,
            },
        )

        db.commit()

        # ========================================================
        # 7. Réponse
        # ========================================================

        return {
            "success": True,
            "ticket": glpi_result,
            "ticket_glpi": {
                "glpi_id": glpi_ticket_id,

                "id_vulnerabilite": uuid_to_string(
                    id_vulnerabilite
                ),

                "id_actif": uuid_to_string(
                    id_actif
                ),

                "id_utilisateur_createur": uuid_to_string(
                    id_utilisateur_createur
                ),

                "priorite": priorite,

                "statut": statut,
            },
        }

    except HTTPException:
        raise

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Erreur GLPI: {str(e)}",
        )


# ============================================================
# GET /glpi/tickets
# Récupérer les tickets GLPI
# ============================================================

@router.get("/tickets")
async def get_glpi_tickets(
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
):
    try:

        service = GLPIService()

        tickets = await service.get_tickets(
            limit=limit,
        )

        return {
            "success": True,
            "count": len(tickets),
            "tickets": tickets,
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Erreur récupération tickets GLPI: {str(e)}"
            ),
        )


# ============================================================
# GET /glpi/tickets/{ticket_id}
# Récupérer un ticket GLPI précis
# ============================================================

@router.get("/tickets/{ticket_id}")
async def get_glpi_ticket(
    ticket_id: int,
):
    try:

        service = GLPIService()

        ticket = await service.get_ticket(
            ticket_id=ticket_id,
        )

        if not ticket:
            raise HTTPException(
                status_code=404,
                detail=(
                    f"Ticket GLPI {ticket_id} introuvable."
                ),
            )

        return {
            "success": True,
            "ticket": ticket,
        }

    except HTTPException:
        raise

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=(
                f"Erreur récupération ticket GLPI: {str(e)}"
            ),
        )


# ============================================================
# POST /glpi/sync
# Synchroniser GLPI → SOC
# ============================================================

@router.post("/sync")
async def sync_glpi_tickets(
    db: Session = Depends(get_db),
):
    """
    Synchronise les tickets GLPI avec la table locale ticket_glpi.

    GLPI reste la source ITSM.
    Le SOC conserve une copie métier minimale pour le portail,
    les statistiques et le Dashboard.
    """

    service = GLPIService()

    try:

        # ========================================================
        # 1. Récupérer les tickets GLPI
        # ========================================================

        glpi_tickets = await service.get_tickets(
            limit=100
        )

        created = 0
        updated = 0

        # ========================================================
        # 2. Parcourir les tickets GLPI
        # ========================================================

        for glpi_ticket in glpi_tickets:

            ticket_data = await service.sync_ticket(
                glpi_ticket
            )

            if not ticket_data:
                continue

            # Identifiant GLPI utilisé comme référence externe
            external_id = ticket_data[
                "identificateur_externe_glpi"
            ]

            # ====================================================
            # 3. Vérifier si le ticket existe déjà dans le SOC
            # ====================================================

            existing = db.execute(
                text(
                    """
                    SELECT id_ticket
                    FROM ticket_glpi
                    WHERE identificateur_externe_glpi =
                          :identificateur_externe_glpi
                    LIMIT 1
                    """
                ),
                {
                    "identificateur_externe_glpi": external_id
                },
            ).mappings().first()

            # ====================================================
            # 4. Ticket existant → UPDATE
            # ====================================================

            if existing:

                db.execute(
                    text(
                        """
                        UPDATE ticket_glpi
                        SET
                            titre = :titre,
                            description = :description,
                            priorite = :priorite,
                            statut = :statut,
                            date_mise_a_jour = :date_mise_a_jour,
                            date_cloture = :date_cloture
                        WHERE identificateur_externe_glpi =
                              :identificateur_externe_glpi
                        """
                    ),
                    ticket_data,
                )

                updated += 1

            # ====================================================
            # 5. Nouveau ticket → INSERT
            # ====================================================

            else:

                # ------------------------------------------------
                # Récupérer un utilisateur SOC existant
                # ------------------------------------------------

                utilisateur = db.execute(
                    text(
                        """
                        SELECT id_utilisateur
                        FROM utilisateur
                        ORDER BY id_utilisateur
                        LIMIT 1
                        """
                    )
                ).mappings().first()

                if not utilisateur:
                    raise HTTPException(
                        status_code=500,
                        detail=(
                            "Aucun utilisateur SOC disponible "
                            "pour associer le ticket GLPI."
                        ),
                    )

                id_utilisateur = utilisateur[
                    "id_utilisateur"
                ]

                # ------------------------------------------------
                # Ajouter l'utilisateur au dictionnaire
                # ------------------------------------------------

                ticket_data[
                    "id_utilisateur_createur"
                ] = id_utilisateur

                # ------------------------------------------------
                # Insérer le ticket local
                # ------------------------------------------------

                db.execute(
                    text(
                        """
                        INSERT INTO ticket_glpi (
                            id_ticket,
                            identificateur_externe_glpi,
                            id_utilisateur_createur,
                            titre,
                            description,
                            priorite,
                            statut,
                            date_creation,
                            date_mise_a_jour,
                            date_cloture
                        )
                        VALUES (
                            UNHEX(REPLACE(UUID(), '-', '')),
                            :identificateur_externe_glpi,
                            :id_utilisateur_createur,
                            :titre,
                            :description,
                            :priorite,
                            :statut,
                            :date_creation,
                            :date_mise_a_jour,
                            :date_cloture
                        )
                        """
                    ),
                    ticket_data,
                )

                created += 1

        # ========================================================
        # 6. Commit
        # ========================================================

        db.commit()

        # ========================================================
        # 7. Réponse
        # ========================================================

        return {
            "success": True,
            "message": "Synchronisation GLPI terminée.",
            "total_glpi": len(glpi_tickets),
            "created": created,
            "updated": updated,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                f"Erreur synchronisation GLPI : {str(e)}"
            ),
        )