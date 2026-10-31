from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class Agent(Base):
    __tablename__="agent"
    id_agent=Column(GUID, primary_key=True, default=uuid.uuid4)
    identifiant_externe=Column(String(100), unique=True)
    nom=Column(String(100), nullable=False)
    adresse_ip=Column(String(45))
    systeme=Column(String(50))
    version=Column(String(20))
    statut=Column(String(30), nullable=False)
    date_derniere_connexion=Column(DateTime(6))
