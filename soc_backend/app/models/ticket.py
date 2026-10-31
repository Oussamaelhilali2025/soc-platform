from sqlalchemy import Column,String,Integer,Boolean,DateTime,JSON,Text,Numeric,ForeignKey
import uuid
from app.core.database import Base,GUID
class TicketGLPI(Base):
    __tablename__="ticket_glpi"
    id_ticket=Column(GUID, primary_key=True, default=uuid.uuid4)
    id_incident=Column(GUID, ForeignKey("incident.id_incident"), nullable=True)
    id_vulnerabilite=Column(GUID, ForeignKey("vulnerabilite.id_vulnerabilite"), nullable=True)
    id_actif=Column(GUID, ForeignKey("actif.id_actif"), nullable=True)
    id_utilisateur_createur=Column(GUID, ForeignKey("utilisateur.id_utilisateur"), nullable=True)
    identificateur_externe_glpi=Column(String(100), unique=True)
    titre=Column(String(255), nullable=False)
    description=Column(String)
    priorite=Column(String(20), nullable=False)
    statut=Column(String(20), nullable=False)
    date_creation=Column(DateTime(6), nullable=False)
    date_mise_a_jour=Column(DateTime(6), nullable=False)
    date_cloture=Column(DateTime(6))
