from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class Actif(Base):
    __tablename__="actif"
    id_actif=Column(GUID, primary_key=True, default=uuid.uuid4)
    nom=Column(String(255), nullable=False)
    type_actif=Column(String(50), nullable=False)
    adresse_ip=Column(String(45))
    adresse_mac=Column(String(17))
    hostname=Column(String(255))
    systeme=Column(String(50))
    environnement=Column(String(50))
    criticite=Column(String(30), nullable=False)
    description=Column(String)
    statut=Column(String(30), nullable=False)
