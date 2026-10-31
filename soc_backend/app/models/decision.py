from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class DecisionAnalyste(Base):
    __tablename__="decision_analyste"
    id_decision=Column(GUID, primary_key=True, default=uuid.uuid4)
    id_alerte=Column(GUID, ForeignKey("alerte.id_alerte"), nullable=True)
    id_incident=Column(GUID, ForeignKey("incident.id_incident"), nullable=True)
    id_evenement=Column(GUID, ForeignKey("evenement.id_evenement"), nullable=True)
    id_utilisateur=Column(GUID, ForeignKey("utilisateur.id_utilisateur"), nullable=True)
    decision=Column(String(40), nullable=False)
    commentaire=Column(String)
    date_decision=Column(DateTime(6), nullable=False)
