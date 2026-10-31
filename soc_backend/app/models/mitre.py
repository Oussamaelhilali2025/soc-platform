from sqlalchemy import Column, String, Text, SmallInteger, ForeignKey
from app.core.database import Base, GUID


class TactiqueMitre(Base):
    __tablename__ = "tactique_mitre"

    id_tactique = Column(String(20), primary_key=True)
    nom = Column(String(100), nullable=False)
    description = Column(Text)


class TechniqueMitre(Base):
    __tablename__ = "technique_mitre"

    id_technique = Column(String(20), primary_key=True)
    nom = Column(String(200), nullable=False)
    description = Column(Text)
    url = Column(String(500))


class TechniqueTactique(Base):
    __tablename__ = "technique_tactique"

    id_technique = Column(
        String(20),
        ForeignKey("technique_mitre.id_technique"),
        primary_key=True,
    )

    id_tactique = Column(
        String(20),
        ForeignKey("tactique_mitre.id_tactique"),
        primary_key=True,
    )


class EvenementMitre(Base):
    __tablename__ = "evenement_mitre"

    id_evenement = Column(
        GUID,
        ForeignKey("evenement.id_evenement"),
        primary_key=True,
    )

    id_technique = Column(
        String(20),
        ForeignKey("technique_mitre.id_technique"),
        primary_key=True,
    )

    source_detection = Column(String(50))
    confiance = Column(SmallInteger)