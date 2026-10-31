# SOC Platform Backend

FastAPI backend for the SOC Platform: MariaDB 10.4.32 + Wazuh + Shuffle + TheHive + GLPI + OpenVAS, designed for a React analyst portal.

## Important
- The existing `soc_platform` database is the source of truth. No automatic table creation and no destructive migrations.
- UUIDs are stored as `BINARY(16)` and converted by the custom `GUID` type; do not use `UUID_TO_BIN()`/`BIN_TO_UUID()` because this MariaDB version does not provide them.
- Pydantic v2 uses `pydantic-settings`.
- React talks only to FastAPI; React never connects directly to MariaDB.

## Run
1. Copy `.env.example` to `.env` and fill values.
2. `python -m venv .venv`
3. Windows: `.venv\\Scripts\\activate` / Linux: `source .venv/bin/activate`
4. `pip install -r requirements.txt`
5. `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`
6. Swagger: `http://localhost:8000/api/v1/docs`

## Wazuh ingestion
`POST /api/v1/ingest/wazuh` accepts a Wazuh alert JSON and stores an `EVENEMENT`. The Wazuh source must already exist in `SOURCE_DONNEES`.

## Next integration layer
Implement real authenticated clients in services for Wazuh, Shuffle, TheHive, GLPI, OpenVAS, VirusTotal and AbuseIPDB. Keep those integrations outside routers.
