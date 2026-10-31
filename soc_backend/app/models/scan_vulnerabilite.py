from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class ScanVulnerabilite(Base):
    __tablename__="scan_vulnerabilite"
    id_scan=Column(GUID, primary_key=True, default=uuid.uuid4)
    identificateur_externe_openvas=Column(String(100), unique=True)
    id_utilisateur=Column(GUID, ForeignKey("utilisateur.id_utilisateur"), nullable=True)
    nom=Column(String(255), nullable=False)
    cible=Column(String(255))
    date_debut=Column(DateTime(6), nullable=False)
    date_fin=Column(DateTime(6))
    statut=Column(String(30), nullable=False)
    niveau_risque=Column(String(30))
    description=Column(String)
