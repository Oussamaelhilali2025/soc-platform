from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class Vulnerabilite(Base):
    __tablename__="vulnerabilite"
    id_vulnerabilite=Column(GUID, primary_key=True, default=uuid.uuid4)
    cve=Column(String(30))
    nom=Column(String(255), nullable=False)
    description=Column(String)
    severite=Column(String(30), nullable=False)
    score_cvss=Column(Numeric(3,1))
    solution=Column(String)
    statut=Column(String(30), nullable=False)
