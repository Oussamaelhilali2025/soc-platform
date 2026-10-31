from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ------------------------------------------------------------------
    # Application
    # ------------------------------------------------------------------

    PROJECT_NAME: str = "SOC Platform"
    SECRET_KEY: str

    API_V1_STR: str = "/api/v1"

    # ------------------------------------------------------------------
    # MariaDB
    # ------------------------------------------------------------------

    MYSQL_USER: str = "root"
    MYSQL_PASSWORD: str = ""
    MYSQL_HOST: str = "127.0.0.1"
    MYSQL_PORT: int = 3306
    MYSQL_DB: str = "soc_platform"

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------

    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7

    # ------------------------------------------------------------------
    # Wazuh Manager API
    # ------------------------------------------------------------------

    WAZUH_API_URL: str = "https://127.0.0.1:55000"

    WAZUH_API_USER: str = "wazuh-wui"

    WAZUH_API_PASSWORD: str = ""

    WAZUH_API_VERIFY_SSL: bool = False

    WAZUH_API_TIMEOUT: float = 15.0

    # False uniquement pour les tests.
    # À passer à False/True selon ton environnement final.
    WAZUH_RESPONSE_DRY_RUN: bool = True

    # ------------------------------------------------------------------
    # Wazuh Indexer / OpenSearch
    #
    # Utilisé pour récupérer les événements COLLECT_LOGS
    # envoyés par l'agent et indexés par Wazuh.
    # ------------------------------------------------------------------

    WAZUH_INDEXER_URL: str = "https://127.0.0.1:9200"

    WAZUH_INDEXER_USER: str = "admin"

    WAZUH_INDEXER_PASSWORD: str = ""

    WAZUH_INDEXER_VERIFY_SSL: bool = False

    WAZUH_INDEXER_TIMEOUT: float = 15.0

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------

    BACKEND_CORS_ORIGINS: str = (
        "http://localhost:3000,"
        "http://localhost:5173"
    )

    # ------------------------------------------------------------------
    # Shuffle
    # ------------------------------------------------------------------

    SHUFFLE_URL: str = "http://127.0.0.1:3001"

    # ------------------------------------------------------------------
    # TheHive
    # ------------------------------------------------------------------

    THEHIVE_URL: str = "http://127.0.0.1:9000"

    THEHIVE_API_KEY: str = ""

    # ------------------------------------------------------------------
    # GLPI
    # ------------------------------------------------------------------

    GLPI_URL: str = "http://127.0.0.1/glpi"

    GLPI_API_TOKEN: str = ""

    GLPI_APP_TOKEN: str = ""

    # ------------------------------------------------------------------
    # VirusTotal / AbuseIPDB
    # ------------------------------------------------------------------

    VT_API_KEY: str = ""

    ABUSEIPDB_API_KEY: str = ""

    # ------------------------------------------------------------------
    # OpenVAS / Greenbone
    # ------------------------------------------------------------------

    OPENVAS_URL: str = ""

    OPENVAS_USERNAME: str = ""

    OPENVAS_PASSWORD: str = ""
        # ------------------------------------------------------------------
    # Greenbone REST Adapter
    # ------------------------------------------------------------------

    GREENBONE_ADAPTER_URL: str = "http://127.0.0.1:8080"

    # ------------------------------------------------------------------
    # Pydantic Settings
    # ------------------------------------------------------------------


    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()