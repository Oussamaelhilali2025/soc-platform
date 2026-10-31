import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/decision-analyste",
    tags=["decision-analyste"],
)


class DecisionAnalysteCreate(BaseModel):
    id_alerte: uuid.UUID | None = None
    id_incident: uuid.UUID | None = None
    id_evenement: uuid.UUID | None = None
    decision: str
    commentaire: str | None = None


class DecisionAnalysteUpdate(BaseModel):
    decision: str | None = None
    commentaire: str | None = None


VALID_DECISIONS = {
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "BENIGN",
    "SUSPICIOUS",
    "MALICIOUS",
    "NEED_INVESTIGATION",
    "ESCALATE",
    "CLOSE",
}


def validate_target(
    db: Session,
    id_alerte,
    id_incident,
    id_evenement,
):
    targets = [
        id_alerte is not None,
        id_incident is not None,
        id_evenement is not None,
    ]

    if sum(targets) != 1:
        raise HTTPException(
            status_code=422,
            detail=(
                "Une décision doit cibler exactement "
                "une alerte, un incident ou un événement."
            ),
        )

    if id_alerte is not None:
        exists = db.execute(
            text(
                """
                SELECT 1
                FROM alerte
                WHERE id_alerte = :id
                """
            ),
            {"id": id_alerte.bytes},
        ).first()

        if not exists:
            raise HTTPException(
                status_code=404,
                detail="Alerte introuvable",
            )

    if id_incident is not None:
        exists = db.execute(
            text(
                """
                SELECT 1
                FROM incident
                WHERE id_incident = :id
                """
            ),
            {"id": id_incident.bytes},
        ).first()

        if not exists:
            raise HTTPException(
                status_code=404,
                detail="Incident introuvable",
            )

    if id_evenement is not None:
        exists = db.execute(
            text(
                """
                SELECT 1
                FROM evenement
                WHERE id_evenement = :id
                """
            ),
            {"id": id_evenement.bytes},
        ).first()

        if not exists:
            raise HTTPException(
                status_code=404,
                detail="Événement introuvable",
            )


@router.post("", status_code=201)
def create_decision(
    payload: DecisionAnalysteCreate,
    db: Session = Depends(get_db),
    current_user=Depends(
        require_permission("INCIDENT_CREATE")
    ),
):
    if payload.decision not in VALID_DECISIONS:
        raise HTTPException(
            status_code=422,
            detail=(
                "Décision invalide. Valeurs autorisées : "
                + ", ".join(sorted(VALID_DECISIONS))
            ),
        )

    validate_target(
        db,
        payload.id_alerte,
        payload.id_incident,
        payload.id_evenement,
    )

    decision_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    db.execute(
        text(
            """
            INSERT INTO decision_analyste (
                id_decision,
                id_alerte,
                id_incident,
                id_evenement,
                id_utilisateur,
                decision,
                commentaire,
                date_decision
            )
            VALUES (
                :id_decision,
                :id_alerte,
                :id_incident,
                :id_evenement,
                :id_utilisateur,
                :decision,
                :commentaire,
                :date_decision
            )
            """
        ),
        {
            "id_decision": decision_id.bytes,
            "id_alerte": (
                payload.id_alerte.bytes
                if payload.id_alerte
                else None
            ),
            "id_incident": (
                payload.id_incident.bytes
                if payload.id_incident
                else None
            ),
            "id_evenement": (
                payload.id_evenement.bytes
                if payload.id_evenement
                else None
            ),
            "id_utilisateur": current_user.id_utilisateur.bytes,
            "decision": payload.decision,
            "commentaire": payload.commentaire,
            "date_decision": now,
        },
    )

    db.commit()

    return {
        "id_decision": str(decision_id),
        "id_alerte": (
            str(payload.id_alerte)
            if payload.id_alerte
            else None
        ),
        "id_incident": (
            str(payload.id_incident)
            if payload.id_incident
            else None
        ),
        "id_evenement": (
            str(payload.id_evenement)
            if payload.id_evenement
            else None
        ),
        "id_utilisateur": str(
            current_user.id_utilisateur
        ),
        "decision": payload.decision,
        "commentaire": payload.commentaire,
        "date_decision": now,
    }


@router.get("")
def list_decisions(
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("INCIDENT_READ")
    ),
):
    rows = db.execute(
        text(
            """
            SELECT
                id_decision,
                id_alerte,
                id_incident,
                id_evenement,
                id_utilisateur,
                decision,
                commentaire,
                date_decision
            FROM decision_analyste
            ORDER BY date_decision DESC
            """
        )
    ).mappings().all()

    return [
        {
            "id_decision": str(
                uuid.UUID(bytes=row["id_decision"])
            ),
            "id_alerte": (
                str(uuid.UUID(bytes=row["id_alerte"]))
                if row["id_alerte"]
                else None
            ),
            "id_incident": (
                str(uuid.UUID(bytes=row["id_incident"]))
                if row["id_incident"]
                else None
            ),
            "id_evenement": (
                str(uuid.UUID(bytes=row["id_evenement"]))
                if row["id_evenement"]
                else None
            ),
            "id_utilisateur": str(
                uuid.UUID(bytes=row["id_utilisateur"])
            ),
            "decision": row["decision"],
            "commentaire": row["commentaire"],
            "date_decision": (
                row["date_decision"].isoformat()
                if row["date_decision"]
                else None
            ),
        }
        for row in rows
    ]


@router.get("/{decision_id}")
def get_decision(
    decision_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("INCIDENT_READ")
    ),
):
    row = db.execute(
        text(
            """
            SELECT
                id_decision,
                id_alerte,
                id_incident,
                id_evenement,
                id_utilisateur,
                decision,
                commentaire,
                date_decision
            FROM decision_analyste
            WHERE id_decision = :id
            """
        ),
        {"id": decision_id.bytes},
    ).mappings().first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Décision analyste introuvable",
        )

    return {
        "id_decision": str(decision_id),
        "id_alerte": (
            str(uuid.UUID(bytes=row["id_alerte"]))
            if row["id_alerte"]
            else None
        ),
        "id_incident": (
            str(uuid.UUID(bytes=row["id_incident"]))
            if row["id_incident"]
            else None
        ),
        "id_evenement": (
            str(uuid.UUID(bytes=row["id_evenement"]))
            if row["id_evenement"]
            else None
        ),
        "id_utilisateur": str(
            uuid.UUID(bytes=row["id_utilisateur"])
        ),
        "decision": row["decision"],
        "commentaire": row["commentaire"],
        "date_decision": (
            row["date_decision"].isoformat()
            if row["date_decision"]
            else None
        ),
    }


@router.put("/{decision_id}")
def update_decision(
    decision_id: uuid.UUID,
    payload: DecisionAnalysteUpdate,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("INCIDENT_CREATE")
    ),
):
    if (
        payload.decision is not None
        and payload.decision not in VALID_DECISIONS
    ):
        raise HTTPException(
            status_code=422,
            detail="Décision invalide",
        )

    existing = db.execute(
        text(
            """
            SELECT id_decision
            FROM decision_analyste
            WHERE id_decision = :id
            """
        ),
        {"id": decision_id.bytes},
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Décision analyste introuvable",
        )

    fields = []
    params = {
        "id": decision_id.bytes,
    }

    if payload.decision is not None:
        fields.append("decision = :decision")
        params["decision"] = payload.decision

    if payload.commentaire is not None:
        fields.append("commentaire = :commentaire")
        params["commentaire"] = payload.commentaire

    if not fields:
        raise HTTPException(
            status_code=422,
            detail="Aucune modification fournie",
        )

    db.execute(
        text(
            f"""
            UPDATE decision_analyste
            SET {", ".join(fields)}
            WHERE id_decision = :id
            """
        ),
        params,
    )

    db.commit()

    return {
        "status": "updated",
        "id_decision": str(decision_id),
    }


@router.delete("/{decision_id}")
def delete_decision(
    decision_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: object = Depends(
        require_permission("INCIDENT_CREATE")
    ),
):
    result = db.execute(
        text(
            """
            DELETE FROM decision_analyste
            WHERE id_decision = :id
            """
        ),
        {"id": decision_id.bytes},
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Décision analyste introuvable",
        )

    db.commit()

    return {
        "status": "deleted",
        "id_decision": str(decision_id),
    }