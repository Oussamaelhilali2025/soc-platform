import sys
import json
import hashlib
import os
import shutil
from datetime import datetime

LOG_FILE = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
QUARANTINE_DIR = r"C:\ProgramData\Wazuh\quarantine"


def log(message):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(
                f"block-hash: {datetime.now():%Y-%m-%d %H:%M:%S} "
                f"{message}\n"
            )
    except Exception:
        pass


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest().lower()


def main():
    try:
        line = sys.stdin.readline()

        if not line:
            log("Aucune entrée STDIN")
            return 1

        data = json.loads(line)

        command = data.get("command")
        parameters = data.get("parameters", {})
        extra_args = parameters.get("extra_args", [])
        alert = parameters.get("alert", {})

        log(
            f"Reçu command={command}, "
            f"extra_args={extra_args}"
        )

        if command != "add":
            log(f"Commande ignorée: {command}")
            return 0

        if not extra_args:
            log("Hash manquant")
            return 1

        expected_hash = str(extra_args[0]).strip().lower()

        if len(expected_hash) != 64:
            log(f"SHA256 invalide: {expected_hash}")
            return 1

        if any(c not in "0123456789abcdef" for c in expected_hash):
            log(f"SHA256 non hexadécimal: {expected_hash}")
            return 1

        alert_data = alert.get("data", {})

        file_path = (
            alert_data.get("path")
            or alert_data.get("file")
            or alert_data.get("filename")
        )

        syscheck = alert.get("syscheck", {})

        if not file_path:
            file_path = syscheck.get("path")

        if not file_path:
            log(
                f"Aucun chemin de fichier fourni pour hash={expected_hash}"
            )
            return 1

        file_path = os.path.normpath(str(file_path))

        if not os.path.isfile(file_path):
            log(f"Fichier introuvable: {file_path}")
            return 1

        calculated_hash = sha256_file(file_path)

        log(
            f"Hash attendu={expected_hash} "
            f"hash calculé={calculated_hash} "
            f"path={file_path}"
        )

        if calculated_hash != expected_hash:
            log("Le hash du fichier ne correspond pas")
            return 1

        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        filename = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        quarantine_path = os.path.join(
            QUARANTINE_DIR,
            f"{timestamp}_{filename}"
        )

        shutil.move(file_path, quarantine_path)

        log(
            f"Fichier mis en quarantaine: "
            f"{file_path} -> {quarantine_path}"
        )

        print(
            json.dumps(
                {
                    "status": "blocked",
                    "hash": expected_hash,
                    "path": file_path,
                    "quarantine": quarantine_path,
                },
                ensure_ascii=False,
            )
        )

        return 0

    except Exception as e:
        log(f"Exception: {repr(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
