import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/evaluation-risque",
    tags=["evaluation-risque"],
)


class EvaluationRisqueCreate(BaseModel):
    id_evenement: uuid.UUID | None = None
    id_alerte: uuid.UUID | None = None

    score_risque: int = Field(
        ge=0,
        le=100
    )

    niveau_risque: str

    action_recommandee: str

    raison: str | None = None

    force_case: bool = False


def validate_target(
    id_evenement,
    id_alerte
):
    """
    Une évaluation doit cibler exactement
    un événement OU une alerte.
    """

    if id_evenement and id_alerte:
        raise HTTPException(
            status_code=422,
            detail=(
                "Une évaluation de risque doit cibler "
                "un événement OU une alerte, pas les deux."
            )
        )

    if not id_evenement and not id_alerte:
        raise HTTPException(
            status_code=422,
            detail=(
                "Une évaluation de risque doit cibler "
                "un événement ou une alerte."
            )
        )


def uuid_bytes(value):
    if value is None:
        return None

    if isinstance(value, uuid.UUID):
        return value.bytes

    return uuid.UUID(str(value)).bytes


def normalize_uuid(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return str(uuid.UUID(bytes=bytes(value)))

    return value


def serialize_row(row):
    if row is None:
        return None

    data = dict(row)

    for key, value in data.items():

        if isinstance(
            value,
            (bytes, bytearray)
        ) and len(value) == 16:
            data[key] = str(
                uuid.UUID(bytes=bytes(value))
            )

        elif isinstance(
            value,
            datetime
        ):
            data[key] = value.isoformat()

    return data


@router.post(
    "",
    status_code=201,
)
def create_evaluation(
    body: EvaluationRisqueCreate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("ALERT_CREATE")
    ),
):
    # ============================================================
    # 1. Validation de la cible
    # ============================================================

    validate_target(
        body.id_evenement,
        body.id_alerte
    )

    # ============================================================
    # 2. Vérifier l'événement
    # ============================================================

    if body.id_evenement:

        event = db.execute(
            text(
                """
                SELECT id_evenement
                FROM evenement
                WHERE id_evenement = :id
                """
            ),
            {
                "id": uuid_bytes(
                    body.id_evenement
                )
            },
        ).mappings().first()

        if not event:
            raise HTTPException(
                status_code=404,
                detail="Événement introuvable"
            )

    # ============================================================
    # 3. Vérifier l'alerte
    # ============================================================

    if body.id_alerte:

        alert = db.execute(
            text(
                """
                SELECT id_alerte
                FROM alerte
                WHERE id_alerte = :id
                """
            ),
            {
                "id": uuid_bytes(
                    body.id_alerte
                )
            },
        ).mappings().first()

        if not alert:
            raise HTTPException(
                status_code=404,
                detail="Alerte introuvable"
            )

    # ============================================================
    # 4. Création
    # ============================================================

    evaluation_id = uuid.uuid4()

    now = datetime.now(timezone.utc)

    db.execute(
        text(
            """
            INSERT INTO evaluation_risque (
                id_evaluation,
                id_evenement,
                id_alerte,
                score_risque,
                niveau_risque,
                action_recommandee,
                raison,
                force_case,
                date_calcul
            )
            VALUES (
                :id_evaluation,
                :id_evenement,
                :id_alerte,
                :score_risque,
                :niveau_risque,
                :action_recommandee,
                :raison,
                :force_case,
                :date_calcul
            )
            """
        ),
        {
            "id_evaluation": evaluation_id.bytes,

            "id_evenement": uuid_bytes(
                body.id_evenement
            ),

            "id_alerte": uuid_bytes(
                body.id_alerte
            ),

            "score_risque": body.score_risque,

            "niveau_risque": body.niveau_risque,

            "action_recommandee": (
                body.action_recommandee
            ),

            "raison": body.raison,

            "force_case": body.force_case,

            "date_calcul": now,
        },
    )

    db.commit()

    # ============================================================
    # 5. Réponse
    # ============================================================

    return {
        "id_evaluation": str(evaluation_id),

        "id_evenement": (
            str(body.id_evenement)
            if body.id_evenement
            else None
        ),

        "id_alerte": (
            str(body.id_alerte)
            if body.id_alerte
            else None
        ),

        "score_risque": body.score_risque,

        "niveau_risque": body.niveau_risque,

        "action_recommandee": (
            body.action_recommandee
        ),

        "raison": body.raison,

        "force_case": body.force_case,

        "message": (
            "Évaluation de risque créée avec succès"
        ),
    }


@router.get(
    "",
    dependencies=[
        Depends(
            require_permission("ALERT_READ")
        )
    ]
)
def list_evaluations(
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
):
    if page < 1:
        raise HTTPException(
            status_code=422,
            detail="page doit être >= 1"
        )

    if page_size < 1 or page_size > 200:
        raise HTTPException(
            status_code=422,
            detail="page_size doit être entre 1 et 200"
        )

    offset = (page - 1) * page_size

    rows = db.execute(
        text(
            """
            SELECT *
            FROM evaluation_risque
            ORDER BY date_calcul DESC
            LIMIT :limit OFFSET :offset
            """
        ),
        {
            "limit": page_size,
            "offset": offset,
        },
    ).mappings().all()

    total = db.execute(
        text(
            """
            SELECT COUNT(*)
            FROM evaluation_risque
            """
        )
    ).scalar_one()

    pages = (
        (total + page_size - 1) // page_size
        if total > 0
        else 0
    )

    return {
        "items": [
            serialize_row(row)
            for row in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


@router.get(
    "/{item_id}",
    dependencies=[
        Depends(
            require_permission("ALERT_READ")
        )
    ]
)
def get_evaluation(
    item_id: uuid.UUID,
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            """
            SELECT *
            FROM evaluation_risque
            WHERE id_evaluation = :id
            """
        ),
        {
            "id": item_id.bytes
        },
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Évaluation de risque introuvable"
        )

    return serialize_row(row)