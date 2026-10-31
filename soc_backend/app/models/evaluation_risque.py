from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class EvaluationRisque(Base):
    __tablename__="evaluation_risque"
    id_evaluation=Column(GUID, primary_key=True, default=uuid.uuid4)
    id_evenement=Column(GUID, ForeignKey("evenement.id_evenement"), nullable=True)
    id_alerte=Column(GUID, ForeignKey("alerte.id_alerte"), nullable=True)
    score_risque=Column(Integer, nullable=False)
    niveau_risque=Column(String(30), nullable=False)
    action_recommandee=Column(String(30), nullable=False)
    raison=Column(String)
    force_case=Column(Boolean)
    date_calcul=Column(DateTime(6), nullable=False)
