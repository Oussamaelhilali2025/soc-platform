from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import MetaData, Table, select, func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_permission

import uuid
import datetime
import decimal


md = MetaData()
_cache = {}


def table(db, name):
    if name not in _cache:
        _cache[name] = Table(
            name,
            md,
            autoload_with=db.bind
        )
    return _cache[name]


def norm(v):
    if isinstance(v, (bytes, bytearray)) and len(v) == 16:
        try:
            return str(uuid.UUID(bytes=bytes(v)))
        except Exception:
            pass

    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat()

    if isinstance(v, decimal.Decimal):
        return float(v)

    return v


def rowdict(row):
    return {
        k: norm(v)
        for k, v in row._mapping.items()
    }


def make_router(
    table_name,
    pk,
    permission,
):
    """
    Router générique en lecture seule.

    table_name : nom réel de la table MariaDB
    pk         : nom réel de la clé primaire
    permission : permission RBAC nécessaire
    """

    if not table_name:
        raise ValueError("table_name obligatoire")

    if not pk:
        raise ValueError(f"PK obligatoire pour {table_name}")

    if not permission:
        raise ValueError(
            f"Permission obligatoire pour {table_name}"
        )

    r = APIRouter(
        prefix=f"/{table_name}",
        tags=[table_name],
    )

    @r.get("")
    def listing(
        page: int = Query(
            1,
            ge=1,
        ),
        page_size: int = Query(
            50,
            ge=1,
            le=200,
        ),
        db: Session = Depends(get_db),
        _: object = Depends(
            require_permission(permission)
        ),
    ):
        t = table(db, table_name)

        total = db.execute(
            select(func.count()).select_from(t)
        ).scalar_one()

        rows = db.execute(
            select(t)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).fetchall()

        pages = (
            (total + page_size - 1)
            // page_size
            if total > 0
            else 0
        )

        return {
            "items": [
                rowdict(row)
                for row in rows
            ],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
        }

    @r.get("/{item_id}")
    def get_one(
        item_id: str,
        db: Session = Depends(get_db),
        _: object = Depends(
            require_permission(permission)
        ),
    ):
        t = table(db, table_name)

        if pk not in t.c:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"Primary key '{pk}' "
                    f"not found in table '{table_name}'"
                ),
            )

        column = t.c[pk]

        try:
            value = uuid.UUID(item_id).bytes
        except ValueError:
            value = item_id

        row = db.execute(
            select(t).where(column == value)
        ).first()

        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"{table_name} not found",
            )

        return rowdict(row)

    return r