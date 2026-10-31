from fastapi import APIRouter

from .auth import router as auth_router
from .dashboard import router as dashboard_router
from .ingest import router as ingest_router
from .alertes import router as alertes_router
from .incidents import router as incidents_router
from .iocs import router as iocs_router
from .evenements import router as evenements_router
from .evenements_reseau import router as evenements_reseau_router
from .evenements_http import router as evenements_http_router
from .generic import make_router
from .evenements_processus import router as evenements_processus_router
from .evenements_ioc import router as evenements_ioc_router
from .threat_intelligence_vt import router as threat_intelligence_vt_router
from .threat_intelligence_abuseipdb import (
    router as threat_intelligence_abuseipdb_router
)
from .technique_tactique import router as technique_tactique_router
from .evenement_mitre import router as evenement_mitre_router
from .regles_detection import router as regles_detection_router
from .regles_correlation import router as regles_correlation_router
from .alerte_evenement import router as alerte_evenement_router
from .incident_evenement import router as incident_evenement_router
from .incident_ioc import router as incident_ioc_router
from .scan_actif import router as scan_actif_router
from .resultat_vulnerabilite import router as resultat_vulnerabilite_router
from .scans_vulnerabilite import router as scans_vulnerabilite_router, frontend_router as vulnerability_frontend_router
from .vulnerabilites import router as vulnerabilites_router
from .evaluation_risque import router as evaluation_risque_router
from .decision_analyste import router as decision_analyste_router
from .shuffle_ingest import router as shuffle_ingest_router
from app.api.v1.response import router as response_router
from .glpi import router as glpi_router
from .admin import router as admin_router



api_router = APIRouter()


# Routers spécifiques
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(ingest_router)
api_router.include_router(alertes_router)
api_router.include_router(incidents_router)
api_router.include_router(iocs_router)
api_router.include_router(evenements_router)
api_router.include_router(evenements_reseau_router)
api_router.include_router(evenements_http_router)
api_router.include_router(evenements_processus_router)
api_router.include_router(evenements_ioc_router)
api_router.include_router(threat_intelligence_vt_router)
api_router.include_router(threat_intelligence_abuseipdb_router)
api_router.include_router(technique_tactique_router)
api_router.include_router(evenement_mitre_router)
api_router.include_router(regles_detection_router)
api_router.include_router(regles_correlation_router)
api_router.include_router(alerte_evenement_router)
api_router.include_router(incident_evenement_router)
api_router.include_router(incident_ioc_router)
api_router.include_router(scan_actif_router)
api_router.include_router(resultat_vulnerabilite_router)
api_router.include_router(scans_vulnerabilite_router)
api_router.include_router(vulnerability_frontend_router)
api_router.include_router(vulnerabilites_router)
api_router.include_router(evaluation_risque_router)
api_router.include_router(decision_analyste_router)
api_router.include_router(shuffle_ingest_router)
api_router.include_router(response_router)
api_router.include_router(glpi_router)
api_router.include_router(admin_router)
# Routes CRUD génériques
ROUTES = [
    ("utilisateur", "id_utilisateur", "USER_READ"),
    ("role", "id_role", "ROLE_MANAGE"),
    ("permission", "id_permission", "ROLE_MANAGE"),
    ("agent", "id_agent", "ASSET_READ"),
    ("actif", "id_actif", "ASSET_READ"),
    ("source_donnees", "id_source", "EVENT_READ"),
    ("evaluation_risque", "id_evaluation", "ALERT_READ"),
    
    ("action_reponse", "id_action", "INCIDENT_READ"),
    ("scan_vulnerabilite", "id_scan", "SCAN_READ"),
    ("vulnerabilite", "id_vulnerabilite", "SCAN_READ"),
    ("ticket_glpi", "id_ticket", "TICKET_READ"),
    ("tactique_mitre", "id_tactique", "EVENT_READ"),
    ("technique_mitre", "id_technique", "EVENT_READ"),
    
]


for table_name, primary_key, permission in ROUTES:
    api_router.include_router(
        make_router(
            table_name,
            pk=primary_key,
            permission=permission
        )
    )