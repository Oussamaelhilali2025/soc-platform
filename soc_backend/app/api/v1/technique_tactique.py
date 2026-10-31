from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import MetaData, Table, select, insert, update, delete
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission


router = APIRouter(
    prefix="/technique-tactique",
    tags=["technique-tactique"]
)

md = MetaData()
_table = None


def get_table(db: Session):
    global _table

    if _table is None:
        _table = Table(
            "technique_tactique",
            md,
            autoload_with=db.bind
        )

    return _table


class TechniqueTactiqueCreate(BaseModel):
    id_technique: str
    id_tactique: str


class TechniqueTactiqueUpdate(BaseModel):
    id_technique: str | None = None
    id_tactique: str | None = None


@router.post(
    "",
    status_code=201,
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def create_relation(
    payload: TechniqueTactiqueCreate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    technique = db.execute(
        select(t).where(
            t.c.id_technique == payload.id_technique,
            t.c.id_tactique == payload.id_tactique
        )
    ).first()

    if technique:
        raise HTTPException(
            status_code=409,
            detail="Cette relation technique/tactique existe déjà"
        )

    # Vérification technique
    technique_exists = db.execute(
        select(1).select_from(
            Table(
                "technique_mitre",
                md,
                autoload_with=db.bind
            )
        ).where(
            md.tables["technique_mitre"].c.id_technique
            == payload.id_technique
        )
    ).first()

    if not technique_exists:
        raise HTTPException(
            status_code=404,
            detail="Technique MITRE introuvable"
        )

    # Vérification tactique
    tactique_table = Table(
        "tactique_mitre",
        md,
        autoload_with=db.bind
    )

    tactique_exists = db.execute(
        select(1).select_from(tactique_table).where(
            tactique_table.c.id_tactique == payload.id_tactique
        )
    ).first()

    if not tactique_exists:
        raise HTTPException(
            status_code=404,
            detail="Tactique MITRE introuvable"
        )

    db.execute(
        insert(t).values(
            id_technique=payload.id_technique,
            id_tactique=payload.id_tactique
        )
    )

    db.commit()

    return {
        "id_technique": payload.id_technique,
        "id_tactique": payload.id_tactique
    }


@router.get(
    "/{id_technique}/{id_tactique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def get_relation(
    id_technique: str,
    id_tactique: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    row = db.execute(
        select(t).where(
            t.c.id_technique == id_technique,
            t.c.id_tactique == id_tactique
        )
    ).first()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Relation technique/tactique introuvable"
        )

    return dict(row._mapping)


@router.put(
    "/{id_technique}/{id_tactique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def update_relation(
    id_technique: str,
    id_tactique: str,
    payload: TechniqueTactiqueUpdate,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    existing = db.execute(
        select(t).where(
            t.c.id_technique == id_technique,
            t.c.id_tactique == id_tactique
        )
    ).first()

    if not existing:
        raise HTTPException(
            status_code=404,
            detail="Relation technique/tactique introuvable"
        )

    new_technique = payload.id_technique or id_technique
    new_tactique = payload.id_tactique or id_tactique

    if (new_technique, new_tactique) != (
        id_technique,
        id_tactique
    ):
        duplicate = db.execute(
            select(t).where(
                t.c.id_technique == new_technique,
                t.c.id_tactique == new_tactique
            )
        ).first()

        if duplicate:
            raise HTTPException(
                status_code=409,
                detail="La nouvelle relation existe déjà"
            )

    db.execute(
        update(t)
        .where(
            t.c.id_technique == id_technique,
            t.c.id_tactique == id_tactique
        )
        .values(
            id_technique=new_technique,
            id_tactique=new_tactique
        )
    )

    db.commit()

    return {
        "id_technique": new_technique,
        "id_tactique": new_tactique
    }


@router.delete(
    "/{id_technique}/{id_tactique}",
    dependencies=[Depends(require_permission("EVENT_READ"))]
)
def delete_relation(
    id_technique: str,
    id_tactique: str,
    db: Session = Depends(get_db)
):
    t = get_table(db)

    result = db.execute(
        delete(t).where(
            t.c.id_technique == id_technique,
            t.c.id_tactique == id_tactique
        )
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Relation technique/tactique introuvable"
        )

    db.commit()

    return {
        "message": "Relation technique/tactique supprimée"
    }