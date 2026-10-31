from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class SourceDonnees(Base):
    __tablename__="source_donnees"
    id_source=Column(GUID, primary_key=True, default=uuid.uuid4)
    nom=Column(String(100), nullable=False, unique=True)
    type_source=Column(String(50), nullable=False)
    version=Column(String(20))
    description=Column(String)
    statut=Column(String(30), nullable=False)
