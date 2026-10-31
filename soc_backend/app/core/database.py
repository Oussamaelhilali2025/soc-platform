import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.types import TypeDecorator, BINARY

from app.core.config import settings


class GUID(TypeDecorator):
    """
    UUID stocké en BINARY(16) pour MariaDB/MySQL.
    """

    impl = BINARY
    cache_ok = True

    def __init__(self, *args, **kwargs):
        super().__init__(length=16)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None

        if isinstance(value, uuid.UUID):
            return value.bytes

        if isinstance(value, str):
            return uuid.UUID(value).bytes

        raise ValueError(f"UUID invalide: {value!r}")

    def process_result_value(self, value, dialect):
        if value is None:
            return None

        if isinstance(value, uuid.UUID):
            return value

        return uuid.UUID(bytes=value)


DATABASE_URL = (
    f"mysql+pymysql://"
    f"{settings.MYSQL_USER}:"
    f"{settings.MYSQL_PASSWORD}@"
    f"{settings.MYSQL_HOST}:"
    f"{settings.MYSQL_PORT}/"
    f"{settings.MYSQL_DB}"
)


engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    pool_recycle=1800,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()