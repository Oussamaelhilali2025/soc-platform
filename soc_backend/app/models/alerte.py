from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class Alerte(Base):
    __tablename__="alerte"
    id_alerte=Column(GUID, primary_key=True, default=uuid.uuid4)
    id_regle_detection=Column(
    GUID,
    nullable=True
)
    id_regle_correlation=Column(
    GUID,
    nullable=True
)
    id_utilisateur_createur=Column(GUID, ForeignKey("utilisateur.id_utilisateur"), nullable=True)
    identifiant_externe=Column(String(100))
    identifiant_thehive=Column(String(100))
    titre=Column(String(255), nullable=False)
    description=Column(String)
    severite=Column(String(30), nullable=False)
    statut=Column(String(30), nullable=False)
    source_alerte=Column(String(30), nullable=False)
    date_creation=Column(DateTime(6), nullable=False)
    date_mise_a_jour=Column(DateTime(6), nullable=False)
    date_cloture=Column(DateTime(6))
