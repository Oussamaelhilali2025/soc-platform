from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class Evenement(Base):
    __tablename__="evenement"
    id_evenement=Column(GUID, primary_key=True, default=uuid.uuid4)
    id_agent=Column(GUID, ForeignKey("agent.id_agent"), nullable=True)
    id_actif=Column(GUID, ForeignKey("actif.id_actif"), nullable=True)
    id_source=Column(GUID, ForeignKey("source_donnees.id_source"), nullable=True)
    identifiant_externe=Column(String(100))
    timestamp_evenement=Column(DateTime(6), nullable=False)
    timestamp_reception=Column(DateTime(6), nullable=False)
    type_evenement=Column(String(50), nullable=False)
    categorie=Column(String(50))
    titre=Column(String(255))
    description=Column(String)
    severite=Column(String(30))
    niveau_wazuh=Column(Integer)
    rule_id_externe=Column(String(100))
    decoder=Column(String(50))
    utilisateur=Column(String(100))
    hostname=Column(String(255))
    localisation=Column(String(100))
    donnees_brutes=Column(JSON, nullable=False)
    donnees_normalisees=Column(JSON)
