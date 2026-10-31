from sqlalchemy import Column, String, DateTime, JSON, ForeignKey
import uuid

from app.core.database import Base, GUID


class ActionReponse(Base):
    __tablename__ = "action_reponse"

    id_action = Column(
        GUID,
        primary_key=True,
        default=uuid.uuid4
    )

    id_utilisateur = Column(
        GUID,
        ForeignKey("utilisateur.id_utilisateur"),
        nullable=True
    )

    id_alerte = Column(
        GUID,
        ForeignKey("alerte.id_alerte"),
        nullable=True
    )

    id_incident = Column(
        GUID,
        ForeignKey("incident.id_incident"),
        nullable=True
    )

    origine_action = Column(
        String(20),
        nullable=False
    )

    type_action = Column(
        String(100),
        nullable=False
    )

    cible = Column(
        String(255),
        nullable=True
    )

    parametres = Column(
        JSON,
        nullable=True
    )

    resultat = Column(
        JSON,
        nullable=True
    )

    statut = Column(
        String(30),
        nullable=False
    )

    date_execution = Column(
        DateTime(6),
        nullable=False
    )