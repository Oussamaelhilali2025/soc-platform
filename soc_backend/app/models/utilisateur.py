import uuid
from datetime import datetime

from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import relationship

from app.core.database import Base, GUID


class Utilisateur(Base):
    __tablename__ = "utilisateur"

    id_utilisateur = Column(
        GUID,
        primary_key=True,
        default=uuid.uuid4,
    )

    nom_utilisateur = Column(
        String(50),
        unique=True,
        nullable=False,
    )

    email = Column(
        String(255),
        unique=True,
        nullable=False,
    )

    mot_de_passe_hash = Column(
        String(255),
        nullable=False,
    )

    nom = Column(
        String(100),
        nullable=False,
    )

    prenom = Column(
        String(100),
        nullable=False,
    )

    statut = Column(
        String(20),
        nullable=False,
    )

    derniere_connexion = Column(
        DateTime(6),
        nullable=True,
    )

    date_creation = Column(
        DateTime(6),
        nullable=False,
        default=datetime.utcnow,
    )

    roles = relationship(
        "Role",
        secondary="utilisateur_role",
        back_populates="users",
    )