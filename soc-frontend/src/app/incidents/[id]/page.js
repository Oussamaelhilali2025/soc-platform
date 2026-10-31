
"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  getIncident,
  getAlert,
  updateIncident,
  getUsers,
  getResponseCatalog,
  getIncidentActions,
  createResponseAction,
  getCollectedLogs,
} from "@/lib/api";
import { useRBAC } from "@/components/auth/RBACContext";

const THEHIVE_URL =
  process.env.NEXT_PUBLIC_THEHIVE_URL || "http://localhost:9000";

/* ================================================================
   HELPERS
================================================================ */

function formatDate(value) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return String(value);
  }
}

function normalizeValue(value) {
  if (value === null || value === undefined || value === "") {
    return "—";
  }

  return String(value);
}

function parseRawData(value) {
  if (!value) {
    return null;
  }

  if (typeof value === "object") {
    return value;
  }

  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  return null;
}

function getAlertRawData(alert) {
  return parseRawData(alert?.evenement?.donnees_brutes);
}

/* ================================================================
   ALERT EXTRACTION HELPERS
================================================================ */

function getAgentIdFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.agent?.id ||
      alert?.evenement?.id_agent ||
      alert?.agent_id ||
      ""
  ).trim();
}

function getAgentIpFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.agent?.ip ||
      raw?.data?.agent_ip ||
      alert?.evenement?.donnees_normalisees?.agent_ip ||
      ""
  ).trim();
}

function getSourceIpFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.data?.srcip ||
      raw?.data?.source_ip ||
      raw?.data?.src_ip ||
      raw?.data?.source?.ip ||
      raw?.srcip ||
      raw?.source_ip ||
      ""
  ).trim();
}

function getDestinationIpFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.data?.dstip ||
      raw?.data?.destination_ip ||
      raw?.data?.dst_ip ||
      raw?.data?.destination?.ip ||
      raw?.dstip ||
      raw?.destination_ip ||
      ""
  ).trim();
}

function getFilePathFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    alert?.evenement?.donnees_normalisees?.windows?.path ||
      alert?.evenement?.donnees_normalisees?.path ||
      raw?.syscheck?.path ||
      raw?.data?.path ||
      raw?.data?.file_path ||
      raw?.data?.file ||
      raw?.data?.filename ||
      ""
  ).trim();
}

function getSha256FromAlert(alert) {
  const raw = getAlertRawData(alert);

  let detectedHash = "";

  if (Array.isArray(alert?.iocs)) {
    const hashIoc = alert.iocs.find(
      (ioc) =>
        String(ioc?.type_ioc || "").toUpperCase() ===
        "HASH_SHA256"
    );

    if (hashIoc?.valeur) {
      detectedHash = String(hashIoc.valeur);
    }
  }

  if (!detectedHash) {
    detectedHash =
      raw?.syscheck?.sha256_after ||
      raw?.data?.sha256_after ||
      raw?.data?.hash ||
      raw?.data?.hashes ||
      "";
  }

  if (typeof detectedHash === "object") {
    detectedHash =
      detectedHash?.sha256 ||
      detectedHash?.SHA256 ||
      "";
  }

  return String(detectedHash)
    .replace(/^SHA256=/i, "")
    .trim();
}

function getProcessIdFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.data?.process_id ||
      raw?.data?.pid ||
      raw?.data?.process?.pid ||
      raw?.process?.pid ||
      raw?.syscheck?.process_id ||
      alert?.evenement?.donnees_normalisees?.process_id ||
      alert?.evenement?.donnees_normalisees?.pid ||
      ""
  ).trim();
}

function getProcessNameFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.data?.process_name ||
      raw?.data?.process?.name ||
      raw?.process?.name ||
      raw?.data?.process ||
      ""
  ).trim();
}

function getHostFromAlert(alert) {
  const raw = getAlertRawData(alert);

  return String(
    raw?.agent?.name ||
      raw?.data?.computer ||
      raw?.data?.hostname ||
      raw?.data?.host ||
      raw?.host?.name ||
      ""
  ).trim();
}

/* ================================================================
   BADGES
================================================================ */

function SeverityBadge({ value }) {
  const severity = String(value || "").toUpperCase();

  const classes = {
    LOW: "border-[var(--border)] bg-white/5 text-[var(--muted)]",
    MEDIUM:
      "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--warning)]",
    HIGH:
      "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)]",
    CRITICAL:
      "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)]",
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${
        classes[severity] ||
        "border-[var(--border)] bg-white/5 text-[var(--muted)]"
      }`}
    >
      {severity || "UNKNOWN"}
    </span>
  );
}

function StatusBadge({ value }) {
  const status = String(value || "").toUpperCase();

  const classes = {
    NEW: "border-blue-400/30 bg-blue-400/10 text-blue-400",
    IN_PROGRESS:
      "border-yellow-400/30 bg-yellow-400/10 text-yellow-400",
    RESOLVED:
      "border-emerald-400/30 bg-emerald-400/10 text-emerald-400",
    CLOSED:
      "border-emerald-400/30 bg-emerald-400/10 text-emerald-400",
    PENDING:
      "border-yellow-400/30 bg-yellow-400/10 text-yellow-400",
    SUCCEEDED:
      "border-emerald-400/30 bg-emerald-400/10 text-emerald-400",
    SUCCESS:
      "border-emerald-400/30 bg-emerald-400/10 text-emerald-400",
    FAILED:
      "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)]",
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${
        classes[status] ||
        "border-[var(--border)] bg-white/5 text-[var(--muted)]"
      }`}
    >
      {normalizeValue(value)}
    </span>
  );
}

/* ================================================================
   UI COMPONENTS
================================================================ */

function InfoItem({ label, value, mono = false }) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-4 transition-colors hover:bg-white/[0.04]">
      <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
        {label}
      </div>

      <div
        className={`break-words text-sm text-[var(--foreground)] ${
          mono ? "font-mono text-xs" : ""
        }`}
      >
        {normalizeValue(value)}
      </div>
    </div>
  );
}

function Section({ title, children, description }) {
  return (
    <section className="rounded-2xl border border-[var(--border)] bg-[var(--card)] shadow-sm">
      <div className="border-b border-[var(--border)] px-5 py-4">
        <h2 className="text-base font-semibold text-[var(--foreground)]">
          {title}
        </h2>

        {description && (
          <p className="mt-1 text-xs text-[var(--muted)]">
            {description}
          </p>
        )}
      </div>

      <div className="p-5">{children}</div>
    </section>
  );
}

/* ================================================================
   PAGE
================================================================ */

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();

  /* ============================================================== 
     RBAC
  ============================================================== */

  const {
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadIncident =
    hasPermission("INCIDENT_READ");

  const canUpdateIncident =
    hasPermission("INCIDENT_UPDATE");

  const canCloseIncident =
    hasPermission("INCIDENT_CLOSE");

  const canReadUsers =
    hasPermission("USER_READ");

  const canCreateTicket =
    hasPermission("TICKET_CREATE");

  const canReadAlert =
    hasPermission("ALERT_READ");

  /* ============================================================== 
     INCIDENT
  ============================================================== */

  const [incident, setIncident] = useState(null);
  const [alert, setAlert] = useState(null);
  const [users, setUsers] = useState([]);

  const [loading, setLoading] = useState(true);
  const [loadingAlert, setLoadingAlert] = useState(false);
  const [loadingUsers, setLoadingUsers] = useState(false);

  const [error, setError] = useState("");
  const [alertError, setAlertError] = useState("");
  const [usersError, setUsersError] = useState("");

  const [saving, setSaving] = useState(false);
  const [saveMessage, setSaveMessage] = useState("");
  const [saveError, setSaveError] = useState("");

  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [assignee, setAssignee] = useState("");

  /* ============================================================== 
     SOC RESPONSE
  ============================================================== */

  const [catalog, setCatalog] = useState([]);
  const [actions, setActions] = useState([]);
  const [loadingActions, setLoadingActions] = useState(false);

  const [selectedAction, setSelectedAction] = useState("");

  const [cible, setCible] = useState("");

  const [hashValue, setHashValue] = useState("");
  const [filePath, setFilePath] = useState("");
  const [processPid, setProcessPid] = useState("");
  const [processName, setProcessName] = useState("");
  const [ipValue, setIpValue] = useState("");
  const [hostValue, setHostValue] = useState("");

  const [agentId, setAgentId] = useState("");

  const [note, setNote] = useState("");

  const [glpiTitle, setGlpiTitle] = useState("");
  const [glpiDescription, setGlpiDescription] = useState("");

  const [submittingAction, setSubmittingAction] =
    useState(false);

  const [actionMessage, setActionMessage] =
    useState("");

  const [actionErrorMsg, setActionErrorMsg] =
    useState("");

  /* ============================================================== 
     TRIAGE
  ============================================================== */

  const [collectedLogs, setCollectedLogs] =
    useState(null);

  const [loadingCollectedLogs, setLoadingCollectedLogs] =
    useState(false);

  const [collectedLogsError, setCollectedLogsError] =
    useState("");

  /* ============================================================== 
     COLLECTED LOGS
  ============================================================== */

  async function loadCollectedLogs(silent = false) {
    if (!params?.id) {
      return null;
    }

    if (!silent) {
      setLoadingCollectedLogs(true);
      setCollectedLogsError("");
    }

    try {
      const data =
        await getCollectedLogs(params.id);

      setCollectedLogs(data);

      return data;
    } catch (err) {
      console.error(
        "Erreur récupération COLLECT_LOGS:",
        err
      );

      if (!silent) {
        setCollectedLogsError(
          err?.message ||
            "Impossible de récupérer les données de triage."
        );
      }

      return null;
    } finally {
      if (!silent) {
        setLoadingCollectedLogs(false);
      }
    }
  }

  function wait(ms) {
    return new Promise((resolve) =>
      setTimeout(resolve, ms)
    );
  }

  async function refreshCollectedLogsAfterAction() {
    const delays = [1000, 2000, 3000];

    for (const delay of delays) {
      await wait(delay);

      try {
        const data =
          await getCollectedLogs(params.id);

        setCollectedLogs(data);

        if (data?.found) {
          setCollectedLogsError("");
          return data;
        }
      } catch (err) {
        console.error(
          "Erreur pendant le polling COLLECT_LOGS:",
          err
        );
      }
    }

    return await loadCollectedLogs();
  }

  /* ============================================================== 
     RESET ACTION FIELDS
  ============================================================== */

  function resetActionFields() {
    setCible("");
    setHashValue("");
    setFilePath("");
    setProcessPid("");
    setProcessName("");
    setIpValue("");
    setHostValue("");
    setGlpiTitle("");
    setGlpiDescription("");
    setNote("");
  }

  /* ============================================================== 
     PREPARE ACTION FROM ALERT
  ============================================================== */

  function prepareActionFromAlert(actionType) {
    setActionMessage("");
    setActionErrorMsg("");

    const detectedAgentId =
      getAgentIdFromAlert(alert);

    if (detectedAgentId) {
      setAgentId(detectedAgentId);
    }

    if (!alert) {
      resetActionFields();
      return;
    }

    if (actionType === "BLOCK_HASH") {
      const detectedHash =
        getSha256FromAlert(alert);

      const detectedPath =
        getFilePathFromAlert(alert);

      setHashValue(detectedHash);
      setFilePath(detectedPath);
      setCible(detectedHash);

      return;
    }

    if (actionType === "KILL_PROCESS") {
      const detectedPid =
        getProcessIdFromAlert(alert);

      const detectedProcessName =
        getProcessNameFromAlert(alert);

      setProcessPid(detectedPid);
      setProcessName(detectedProcessName);
      setCible(detectedPid);

      return;
    }

    if (actionType === "BLOCK_IP") {
      const sourceIp =
        getSourceIpFromAlert(alert);

      setIpValue(sourceIp);
      setCible(sourceIp);

      return;
    }

    if (actionType === "ISOLATE_HOST") {
      const detectedHost =
        getHostFromAlert(alert);

      const detectedIp =
        getAgentIpFromAlert(alert);

      setHostValue(
        detectedHost || detectedIp
      );

      setCible(
        detectedIp || detectedHost
      );

      return;
    }

    if (actionType === "CREATE_GLPI_TICKET") {
      setGlpiTitle(
        incident?.titre ||
          alert?.titre ||
          "Incident de sécurité"
      );

      setGlpiDescription(
        incident?.description ||
          alert?.description ||
          ""
      );

      return;
    }

    resetActionFields();
  }

  /* ============================================================== 
     RESPONSE ACTION PERMISSION
  ============================================================== */

  function canExecuteResponseAction(actionType) {
    if (!actionType) {
      return false;
    }

    if (actionType === "CLOSE_INCIDENT") {
      return canCloseIncident;
    }

    if (actionType === "CREATE_GLPI_TICKET") {
      return canCreateTicket;
    }

    return canUpdateIncident;
  }

  /* ============================================================== 
     LOAD INCIDENT
  ============================================================== */

  useEffect(() => {
    let cancelled = false;

    async function loadIncident() {
      if (!params?.id || !canReadIncident) {
        return;
      }

      try {
        setLoading(true);
        setError("");

        const data =
          await getIncident(params.id);

        if (cancelled) {
          return;
        }

        setIncident(data);
        setStatus(data?.statut || "");
        setPriority(data?.priorite || "");
        setAssignee(
          data?.id_utilisateur_assigne || ""
        );

        /* ----------------------------------------------------------
           USERS
        ---------------------------------------------------------- */

        if (canReadUsers) {
          try {
            setLoadingUsers(true);
            setUsersError("");

            const usersData =
              await getUsers();

            if (!cancelled) {
              setUsers(
                Array.isArray(usersData)
                  ? usersData
                  : Array.isArray(usersData?.items)
                    ? usersData.items
                    : []
              );
            }
          } catch (err) {
            if (!cancelled) {
              setUsersError(
                err?.message ||
                  "Impossible de charger les analystes."
              );
            }
          } finally {
            if (!cancelled) {
              setLoadingUsers(false);
            }
          }
        } else {
          setUsers([]);
          setLoadingUsers(false);
          setUsersError("");
        }

        /* ----------------------------------------------------------
           ALERT
        ---------------------------------------------------------- */

        if (data?.id_alerte) {
          try {
            setLoadingAlert(true);
            setAlertError("");

            const alertData =
              await getAlert(data.id_alerte);

            if (!cancelled) {
              setAlert(alertData);

              const detectedAgentId =
                getAgentIdFromAlert(alertData);

              if (detectedAgentId) {
                setAgentId(
                  detectedAgentId
                );
              }
            }
          } catch (err) {
            if (!cancelled) {
              setAlertError(
                err?.message ||
                  "Impossible de charger l’alerte associée."
              );
            }
          } finally {
            if (!cancelled) {
              setLoadingAlert(false);
            }
          }
        }

        /* ----------------------------------------------------------
           RESPONSE CATALOG + HISTORY
        ---------------------------------------------------------- */

        try {
          setLoadingActions(true);
          setActionErrorMsg("");

          const [cat, acts] =
            await Promise.all([
              getResponseCatalog(),
              getIncidentActions(
                params.id
              ),
            ]);

          if (!cancelled) {
            setCatalog(
              Array.isArray(cat)
                ? cat
                : Array.isArray(cat?.items)
                  ? cat.items
                  : []
            );

            setActions(
              Array.isArray(acts)
                ? acts
                : Array.isArray(acts?.items)
                  ? acts.items
                  : []
            );
          }
        } catch (err) {
          console.error(
            "RESPONSE API ERROR:",
            err
          );

          if (!cancelled) {
            setCatalog([]);
            setActions([]);
            setActionErrorMsg(
              err?.message ||
                "Impossible de charger le catalogue de réponse."
            );
          }
        } finally {
          if (!cancelled) {
            setLoadingActions(false);
          }
        }

        /* ----------------------------------------------------------
           TRIAGE
        ---------------------------------------------------------- */

        if (!cancelled) {
          await loadCollectedLogs(true);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err?.message ||
              "Impossible de charger l’incident."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    loadIncident();

    return () => {
      cancelled = true;
    };
  }, [params?.id, canReadIncident, canReadUsers]);

  /* ============================================================== 
     SAVE INCIDENT
  ============================================================== */

  async function handleSave() {
    if (
      !params?.id ||
      saving ||
      !canUpdateIncident
    ) {
      return;
    }

    try {
      setSaving(true);
      setSaveError("");
      setSaveMessage("");

      const payload = {
        statut: status || null,
        priorite: priority || null,
        id_utilisateur_assigne:
          assignee || null,
      };

      await updateIncident(
        params.id,
        payload
      );

      const refreshed =
        await getIncident(params.id);

      setIncident(refreshed);
      setStatus(
        refreshed?.statut || ""
      );
      setPriority(
        refreshed?.priorite || ""
      );
      setAssignee(
        refreshed?.id_utilisateur_assigne ||
          ""
      );

      setSaveMessage(
        "Incident mis à jour avec succès."
      );
    } catch (err) {
      setSaveError(
        err?.message ||
          "Impossible de mettre à jour l’incident."
      );
    } finally {
      setSaving(false);
    }
  }

  /* ============================================================== 
     RESPONSE ACTION
  ============================================================== */

  async function handleResponseAction() {
    if (
      !params?.id ||
      !selectedAction ||
      submittingAction ||
      !canExecuteResponseAction(selectedAction)
    ) {
      return;
    }

    try {
      setSubmittingAction(true);
      setActionMessage("");
      setActionErrorMsg("");

      const parametres = {};

      /* ------------------------------------------------------------
         AGENT WAZUH
      ------------------------------------------------------------ */

      let resolvedAgentId =
        agentId.trim();

      if (!resolvedAgentId) {
        resolvedAgentId =
          getAgentIdFromAlert(alert);
      }

      if (
        resolvedAgentId &&
        selectedAction !== "CREATE_GLPI_TICKET"
      ) {
        parametres.agent_id =
          resolvedAgentId;
      }

      /* ------------------------------------------------------------
         NOTE
      ------------------------------------------------------------ */

      if (note.trim()) {
        parametres.note =
          note.trim();
      }

      /* ------------------------------------------------------------
         CLOSE INCIDENT
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "CLOSE_INCIDENT"
      ) {
        parametres.statut =
          "CLOSED";
      }

      /* ------------------------------------------------------------
         ADD NOTE
      ------------------------------------------------------------ */

      if (
        selectedAction === "ADD_NOTE" &&
        !note.trim()
      ) {
        throw new Error(
          "Une note est requise pour ADD_NOTE."
        );
      }

      /* ------------------------------------------------------------
         BLOCK HASH
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "BLOCK_HASH"
      ) {
        const finalHash =
          hashValue.trim() ||
          getSha256FromAlert(alert);

        const finalFilePath =
          filePath.trim() ||
          getFilePathFromAlert(alert);

        if (!finalHash) {
          throw new Error(
            "Impossible de déterminer le SHA256 depuis l’alerte."
          );
        }

        if (!finalFilePath) {
          throw new Error(
            "Impossible de déterminer le chemin du fichier depuis l’alerte."
          );
        }

        if (
          !/^[a-fA-F0-9]{64}$/.test(
            finalHash
          )
        ) {
          throw new Error(
            "Le SHA256 doit contenir exactement 64 caractères hexadécimaux."
          );
        }

        parametres.hash =
          finalHash;

        parametres.file_path =
          finalFilePath;
      }

      /* ------------------------------------------------------------
         BLOCK IP
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "BLOCK_IP"
      ) {
        const finalIp =
          ipValue.trim() ||
          cible.trim() ||
          getSourceIpFromAlert(alert);

        if (!finalIp) {
          throw new Error(
            "Une IP cible est requise pour BLOCK_IP."
          );
        }

        parametres.ip =
          finalIp;
      }

      /* ------------------------------------------------------------
         ISOLATE HOST
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "ISOLATE_HOST"
      ) {
        const finalHost =
          hostValue.trim() ||
          cible.trim() ||
          getAgentIpFromAlert(alert) ||
          getHostFromAlert(alert);

        if (!finalHost) {
          throw new Error(
            "Impossible de déterminer l’hôte à isoler."
          );
        }

        parametres.host =
          finalHost;
      }

      /* ------------------------------------------------------------
         KILL PROCESS
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "KILL_PROCESS"
      ) {
        const finalPid =
          processPid.trim() ||
          cible.trim() ||
          getProcessIdFromAlert(alert);

        if (!finalPid) {
          throw new Error(
            "Le PID du processus est requis pour KILL_PROCESS."
          );
        }

        if (!/^\d+$/.test(finalPid)) {
          throw new Error(
            "Le PID doit être numérique."
          );
        }

        parametres.pid =
          finalPid;

        if (processName.trim()) {
          parametres.process_name =
            processName.trim();
        }
      }

      /* ------------------------------------------------------------
         CREATE GLPI TICKET
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "CREATE_GLPI_TICKET"
      ) {
        if (!glpiTitle.trim()) {
          throw new Error(
            "Le titre du ticket GLPI est requis."
          );
        }

        if (!glpiDescription.trim()) {
          throw new Error(
            "La description du ticket GLPI est requise."
          );
        }

        parametres.title =
          glpiTitle.trim();

        parametres.description =
          glpiDescription.trim();
      }

      /* ------------------------------------------------------------
         COLLECT LOGS
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "COLLECT_LOGS"
      ) {
        /* L'agent Wazuh suffit. */
      }

      /* ------------------------------------------------------------
         CIBLE FINALE
      ------------------------------------------------------------ */

      let finalCible =
        cible.trim() || null;

      if (
        selectedAction ===
        "BLOCK_HASH"
      ) {
        finalCible =
          hashValue.trim() ||
          getSha256FromAlert(alert) ||
          null;
      }

      if (
        selectedAction ===
        "BLOCK_IP"
      ) {
        finalCible =
          ipValue.trim() ||
          getSourceIpFromAlert(alert) ||
          null;
      }

      if (
        selectedAction ===
        "ISOLATE_HOST"
      ) {
        finalCible =
          hostValue.trim() ||
          getAgentIpFromAlert(alert) ||
          getHostFromAlert(alert) ||
          null;
      }

      if (
        selectedAction ===
        "KILL_PROCESS"
      ) {
        finalCible =
          processPid.trim() ||
          getProcessIdFromAlert(alert) ||
          null;
      }

      if (
        selectedAction ===
          "COLLECT_LOGS" ||
        selectedAction === "ADD_NOTE" ||
        selectedAction === "CLOSE_INCIDENT" ||
        selectedAction === "CREATE_GLPI_TICKET"
      ) {
        finalCible = null;
      }

      /* ------------------------------------------------------------
         DEBUG
      ------------------------------------------------------------ */

      console.log(
        "SOC RESPONSE PAYLOAD:",
        {
          id_incident: params.id,
          type_action:
            selectedAction,
          cible: finalCible,
          parametres,
          origine_action: "MANUAL",
        }
      );

      /* ------------------------------------------------------------
         API
      ------------------------------------------------------------ */

      const result =
        await createResponseAction({
          id_incident: params.id,
          type_action:
            selectedAction,
          cible: finalCible,
          parametres,
          origine_action: "MANUAL",
        });

      /* ------------------------------------------------------------
         MESSAGE
      ------------------------------------------------------------ */

      if (
        result?.statut ===
        "FAILED"
      ) {
        setActionErrorMsg(
          result?.resultat?.message ||
            result?.message ||
            "L’action a échoué."
        );
      } else {
        setActionMessage(
          result?.message ||
            `Action ${selectedAction} exécutée avec succès.`
        );
      }

      /* ------------------------------------------------------------
         REFRESH HISTORY + INCIDENT
      ------------------------------------------------------------ */

      const [
        acts,
        refreshed,
      ] = await Promise.all([
        getIncidentActions(
          params.id
        ),
        getIncident(
          params.id
        ),
      ]);

      setActions(
        Array.isArray(acts)
          ? acts
          : Array.isArray(acts?.items)
            ? acts.items
            : []
      );

      setIncident(refreshed);

      setStatus(
        refreshed?.statut || ""
      );

      setPriority(
        refreshed?.priorite || ""
      );

      setAssignee(
        refreshed?.id_utilisateur_assigne ||
          ""
      );

      /* ------------------------------------------------------------
         COLLECT LOGS
      ------------------------------------------------------------ */

      if (
        selectedAction ===
        "COLLECT_LOGS" &&
        result?.statut !== "FAILED"
      ) {
        setActionMessage(
          "Collecte lancée. Attente des données Wazuh..."
        );

        const triage =
          await refreshCollectedLogsAfterAction();

        if (triage?.found) {
          setActionMessage(
            "Collecte terminée. Données de triage actualisées."
          );
        } else {
          setActionMessage(
            "Collecte envoyée. Les données de triage ne sont pas encore disponibles."
          );
        }
      } else {
        await loadCollectedLogs(true);
      }

      /* ------------------------------------------------------------
         RESET
      ------------------------------------------------------------ */

      if (
        result?.statut !== "FAILED"
      ) {
        setNote("");

        if (
          selectedAction ===
          "BLOCK_HASH"
        ) {
          setCible(
            hashValue
          );
        } else {
          setCible("");
        }
      }
    } catch (err) {
      console.error(
        "Erreur action SOC:",
        err
      );

      setActionErrorMsg(
        err?.message ||
          "Échec de l’action de réponse."
      );
    } finally {
      setSubmittingAction(false);
    }
  }

  /* ============================================================== 
     LOADING / RBAC
  ============================================================== */

  if (rbacLoading) {
    return (
      <main className="min-h-screen p-6">
        <div className="mx-auto max-w-7xl">
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-8 text-sm text-[var(--muted)]">
            Vérification des permissions...
          </div>
        </div>
      </main>
    );
  }

  if (!canReadIncident) {
    return (
      <main className="min-h-screen p-6">
        <div className="mx-auto max-w-2xl">
          <div className="rounded-2xl border border-[var(--critical)]/40 bg-[var(--critical)]/5 p-6">
            <div className="text-sm font-semibold text-[var(--critical)]">
              Accès refusé
            </div>

            <div className="mt-2 text-sm text-[var(--muted)]">
              Votre compte ne possède pas la permission nécessaire
              pour consulter cet incident.
            </div>

            <button
              type="button"
              onClick={() => router.back()}
              className="mt-4 rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium transition-colors hover:bg-white/[0.04]"
            >
              Retour
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (loading) {
    return (
      <main className="min-h-screen p-6">
        <div className="mx-auto max-w-7xl">
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-8 text-sm text-[var(--muted)]">
            Chargement de l’incident...
          </div>
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="min-h-screen p-6">
        <div className="mx-auto max-w-7xl">
          <div className="rounded-2xl border border-[var(--critical)]/40 bg-[var(--critical)]/5 p-6 text-sm text-[var(--critical)]">
            {error}
          </div>
        </div>
      </main>
    );
  }

  if (!incident) {
    return (
      <main className="min-h-screen p-6">
        <div className="mx-auto max-w-7xl">
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-6 text-sm text-[var(--muted)]">
            Incident introuvable.
          </div>
        </div>
      </main>
    );
  }

  const incidentId =
    incident.id_incident ||
    params.id;

  const alertId =
    incident.id_alerte;

  const theHiveId =
    incident.identifiant_thehive;

  const selectedActionAllowed =
    canExecuteResponseAction(selectedAction);

  /* ================================================================
     RENDER
  ================================================================ */

  return (
    <main className="min-h-screen space-y-6 p-6">
      <div className="mx-auto max-w-7xl space-y-6">

        {/* =========================================================
            HEADER
        ========================================================= */}

        <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-6 shadow-sm">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">

            <div className="min-w-0">

              <button
                type="button"
                onClick={() =>
                  router.push(
                    "/incidents"
                  )
                }
                className="mb-5 inline-flex items-center gap-2 text-sm text-[var(--muted)] transition-colors hover:text-[var(--foreground)]"
              >
                <span>←</span>
                Retour aux incidents
              </button>

              <div className="mb-2 text-xs font-medium uppercase tracking-wider text-[var(--muted)]">
                Gestion des incidents
              </div>

              <h1 className="break-words text-2xl font-bold tracking-tight text-[var(--foreground)] lg:text-3xl">
                {normalizeValue(
                  incident.titre
                )}
              </h1>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                <SeverityBadge
                  value={
                    incident.severite
                  }
                />

                <StatusBadge
                  value={
                    incident.statut
                  }
                />

                {theHiveId && (
                  <span className="inline-flex items-center rounded-full border border-emerald-400/30 bg-emerald-400/10 px-3 py-1 text-xs font-semibold text-emerald-400">
                    TheHive associé
                  </span>
                )}
              </div>
            </div>

            <div className="flex flex-wrap gap-2">

              {theHiveId && (
                <a
                  href={THEHIVE_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center justify-center rounded-lg border border-[var(--border)] bg-white/[0.02] px-4 py-2 text-sm font-medium transition-colors hover:bg-white/[0.06]"
                >
                  Ouvrir TheHive
                </a>
              )}

              {alertId && canReadAlert && (
                <button
                  type="button"
                  onClick={() =>
                    router.push(
                      `/alerts/${alertId}`
                    )
                  }
                  className="inline-flex items-center justify-center rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
                >
                  Voir l’alerte
                </button>
              )}

            </div>
          </div>
        </div>

        {/* =========================================================
            INFORMATIONS
        ========================================================= */}

        <Section
          title="Informations de l’incident"
          description="Informations générales et traçabilité de l’incident."
        >
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">

            <InfoItem
              label="Identifiant"
              value={incidentId}
              mono
            />

            <InfoItem
              label="Alerte associée"
              value={alertId}
              mono
            />

            <InfoItem
              label="Case TheHive"
              value={theHiveId}
              mono
            />

            <InfoItem
              label="Sévérité"
              value={incident.severite}
            />

            <InfoItem
              label="Priorité"
              value={incident.priorite}
            />

            <InfoItem
              label="Statut"
              value={incident.statut}
            />

            <InfoItem
              label="Actif"
              value={incident.id_actif}
              mono
            />

            <InfoItem
              label="Créateur"
              value={
                incident.createur_prenom &&
                incident.createur_nom
                  ? `${incident.createur_prenom} ${incident.createur_nom}`
                  : incident.id_utilisateur_createur
              }
            />

            <InfoItem
              label="Assigné à"
              value={
                incident.assigne_prenom &&
                incident.assigne_nom
                  ? `${incident.assigne_prenom} ${incident.assigne_nom}`
                  : "—"
              }
            />

            <InfoItem
              label="Date de création"
              value={formatDate(
                incident.date_creation
              )}
            />

            <InfoItem
              label="Dernière mise à jour"
              value={formatDate(
                incident.date_mise_a_jour
              )}
            />

            <InfoItem
              label="Date de clôture"
              value={formatDate(
                incident.date_cloture
              )}
            />

          </div>
        </Section>

        {/* =========================================================
            DESCRIPTION
        ========================================================= */}

        <Section
          title="Description"
          description="Description associée à l’incident."
        >
          <div className="whitespace-pre-wrap rounded-xl border border-[var(--border)] bg-black/5 p-5 text-sm leading-7 text-[var(--foreground)]">
            {normalizeValue(
              incident.description
            )}
          </div>
        </Section>

        {/* =========================================================
            GESTION
        ========================================================= */}

        <Section
          title="Gestion de l’incident"
          description="Mise à jour du statut, de la priorité et de l’analyste responsable."
        >
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">

            <div>
              <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                Statut
              </label>

              <select
                value={status}
                onChange={(e) =>
                  setStatus(
                    e.target.value
                  )
                }
                disabled={!canUpdateIncident}
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--card)] px-3 py-2.5 text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
              >
                <option value="">
                  Sélectionner
                </option>

                <option value="NEW">
                  NEW
                </option>

                <option value="IN_PROGRESS">
                  IN_PROGRESS
                </option>

                <option value="RESOLVED">
                  RESOLVED
                </option>

                <option value="CLOSED">
                  CLOSED
                </option>
              </select>
            </div>

            <div>
              <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                Priorité
              </label>

              <select
                value={priority}
                onChange={(e) =>
                  setPriority(
                    e.target.value
                  )
                }
                disabled={!canUpdateIncident}
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--card)] px-3 py-2.5 text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
              >
                <option value="">
                  Sélectionner
                </option>

                <option value="LOW">
                  LOW
                </option>

                <option value="MEDIUM">
                  MEDIUM
                </option>

                <option value="HIGH">
                  HIGH
                </option>

                <option value="CRITICAL">
                  CRITICAL
                </option>
              </select>
            </div>

            <div>
              <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                Analyste assigné
              </label>

              <select
                value={assignee}
                onChange={(e) =>
                  setAssignee(
                    e.target.value
                  )
                }
                disabled={
                  !canUpdateIncident ||
                  !canReadUsers ||
                  loadingUsers
                }
                className="w-full rounded-lg border border-[var(--border)] bg-[var(--card)] px-3 py-2.5 text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
              >
                <option value="">
                  {loadingUsers
                    ? "Chargement..."
                    : "Aucun analyste"}
                </option>

                {users.map(
                  (user) => (
                    <option
                      key={
                        user.id_utilisateur
                      }
                      value={
                        user.id_utilisateur
                      }
                    >
                      {user.prenom}{" "}
                      {user.nom} (
                      {
                        user.nom_utilisateur
                      }
                      )
                    </option>
                  )
                )}
              </select>

              {usersError && (
                <div className="mt-2 text-xs text-[var(--critical)]">
                  {usersError}
                </div>
              )}
            </div>

          </div>

          <div className="mt-5 flex flex-wrap items-center gap-3">

            <button
              type="button"
              onClick={handleSave}
              disabled={
                !canUpdateIncident ||
                saving
              }
              className="rounded-lg bg-[var(--accent)] px-5 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving
                ? "Enregistrement..."
                : "Enregistrer"}
            </button>

            {saveMessage && (
              <span className="rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-400">
                {saveMessage}
              </span>
            )}

            {saveError && (
              <span className="rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/10 px-3 py-2 text-sm text-[var(--critical)]">
                {saveError}
              </span>
            )}

          </div>
        </Section>

        {/* =========================================================
            SOC RESPONSE
        ========================================================= */}

        <Section
          title="SOC Response"
          description="Actions de réponse et de containment exécutées sur l’environnement de sécurité."
        >
          {loadingActions ? (

            <div className="flex items-center gap-3 rounded-xl border border-[var(--border)] bg-white/[0.02] p-5 text-sm text-[var(--muted)]">
              <div className="h-4 w-4 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
              Chargement des actions de réponse...
            </div>

          ) : (

            <div className="space-y-6">

              {actionErrorMsg &&
                catalog.length === 0 && (
                  <div className="flex items-start gap-3 rounded-xl border border-[var(--critical)]/30 bg-[var(--critical)]/5 p-4">
                    <div className="mt-0.5 text-[var(--critical)]">
                      ⚠
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-[var(--critical)]">
                        Service de réponse indisponible
                      </div>

                      <div className="mt-1 text-xs text-[var(--muted)]">
                        {actionErrorMsg}
                      </div>
                    </div>
                  </div>
                )}

              {/* RESPONSE CONSOLE */}

              <div className="rounded-2xl border border-[var(--border)] bg-gradient-to-r from-[var(--accent)]/[0.08] to-transparent p-5">

                <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">

                  <div className="flex items-center gap-3">

                    <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--accent)]/15 text-lg">
                      🛡
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-[var(--foreground)]">
                        Response Console
                      </div>

                      <div className="mt-0.5 text-xs text-[var(--muted)]">
                        Intervention manuelle depuis le SOC
                      </div>
                    </div>

                  </div>

                  <div className="flex w-fit items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/5 px-3 py-2">
                    <span className="h-2 w-2 rounded-full bg-emerald-400" />

                    <span className="text-xs font-medium text-emerald-400">
                      Response Engine Ready
                    </span>
                  </div>

                </div>
              </div>

              {/* ACTION SELECTION */}

              <div>

                <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">

                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                      01 · Action
                    </div>

                    <div className="mt-1 text-sm text-[var(--foreground)]">
                      Sélectionner une action de réponse
                    </div>
                  </div>

                  {selectedAction && (
                    <span className="w-fit rounded-full border border-[var(--accent)]/30 bg-[var(--accent)]/10 px-3 py-1 font-mono text-xs font-medium text-[var(--accent)]">
                      {selectedAction}
                    </span>
                  )}

                </div>

                {catalog.length > 0 ? (

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">

                    {catalog
                      .filter((item) =>
                        canExecuteResponseAction(
                          item.type_action
                        )
                      )
                      .map(
                        (item) => {

                          const type =
                            item.type_action;

                          const selected =
                            selectedAction ===
                            type;

                          return (
                            <button
                              key={type}
                              type="button"
                              onClick={() => {
                                setSelectedAction(
                                  type
                                );

                                prepareActionFromAlert(
                                  type
                                );
                              }}
                              className={`group rounded-xl border p-4 text-left transition-all ${
                                selected
                                  ? "border-[var(--accent)] bg-[var(--accent)]/10 shadow-[0_0_0_1px_var(--accent)]"
                                  : "border-[var(--border)] bg-white/[0.02] hover:border-[var(--accent)]/40 hover:bg-white/[0.04]"
                              }`}
                            >

                              <div className="flex items-start justify-between gap-3">

                                <div>
                                  <div className="text-sm font-semibold text-[var(--foreground)]">
                                    {item.label ||
                                      type}
                                  </div>

                                  <div className="mt-1 text-[10px] font-medium uppercase tracking-wider text-[var(--muted)]">
                                    {item.phase ||
                                      "RESPONSE"}
                                  </div>
                                </div>

                                <div
                                  className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-xs ${
                                    selected
                                      ? "bg-[var(--accent)] text-white"
                                      : "bg-white/[0.05] text-[var(--muted)]"
                                  }`}
                                >
                                  {selected
                                    ? "✓"
                                    : "→"}
                                </div>

                              </div>

                              <div className="mt-3 font-mono text-[10px] text-[var(--muted)]">
                                {type}
                              </div>

                            </button>
                          );
                        }
                      )}

                  </div>

                ) : !actionErrorMsg ? (

                  <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-5 text-sm text-[var(--muted)]">
                    Aucune action de réponse disponible.
                  </div>

                ) : null}

              </div>

              {/* =====================================================
                  DYNAMIC ACTION CONFIGURATION
              ===================================================== */}

              {selectedAction &&
                selectedActionAllowed && (

                <div className="overflow-hidden rounded-2xl border border-[var(--border)] bg-white/[0.02]">

                  <div className="border-b border-[var(--border)] px-5 py-4">

                    <div className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                      02 · Configuration de l’action
                    </div>

                    <div className="mt-1 text-sm text-[var(--foreground)]">
                      Paramètres nécessaires à cette intervention
                    </div>

                  </div>

                  <div className="space-y-5 p-5">

                    {/* BLOCK HASH */}

                    {selectedAction ===
                      "BLOCK_HASH" && (

                      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            SHA256
                          </label>

                          <input
                            value={
                              hashValue
                            }
                            onChange={(e) =>
                              setHashValue(
                                e.target.value
                              )
                            }
                            placeholder="SHA256 du fichier"
                            disabled={!canUpdateIncident}
                            className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-xs text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />

                          <div className="mt-2 text-xs text-[var(--muted)]">
                            Récupéré automatiquement depuis l’alerte FIM lorsque disponible.
                          </div>
                        </div>

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            Chemin du fichier
                          </label>

                          <input
                            value={
                              filePath
                            }
                            onChange={(e) =>
                              setFilePath(
                                e.target.value
                              )
                            }
                            placeholder="C:\Users\...\fichier.exe"
                            disabled={!canUpdateIncident}
                            className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-xs text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />

                          <div className="mt-2 text-xs text-[var(--muted)]">
                            Nécessaire pour vérifier le hash puis placer le fichier en quarantaine.
                          </div>
                        </div>

                      </div>
                    )}

                    {/* KILL PROCESS */}

                    {selectedAction ===
                      "KILL_PROCESS" && (

                      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            PID du processus
                          </label>

                          <input
                            type="text"
                            inputMode="numeric"
                            value={
                              processPid
                            }
                            onChange={(e) => {
                              const value =
                                e.target.value.replace(
                                  /\D/g,
                                  ""
                                );

                              setProcessPid(
                                value
                              );

                              setCible(
                                value
                              );
                            }}
                            placeholder="Ex. 25772"
                            disabled={!canUpdateIncident}
                            className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />

                          <div className="mt-2 text-xs text-[var(--muted)]">
                            Le PID peut être récupéré depuis l’alerte ou saisi manuellement.
                          </div>
                        </div>

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            Processus
                          </label>

                          <input
                            value={
                              processName
                            }
                            onChange={(e) =>
                              setProcessName(
                                e.target.value
                              )
                            }
                            placeholder="Nom du processus"
                            disabled={!canUpdateIncident}
                            className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />
                        </div>

                      </div>
                    )}

                    {/* BLOCK IP */}

                    {selectedAction ===
                      "BLOCK_IP" && (

                      <div>

                        <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                          Adresse IP à bloquer
                        </label>

                        <input
                          value={
                            ipValue
                          }
                          onChange={(e) => {
                            setIpValue(
                              e.target.value
                            );

                            setCible(
                              e.target.value
                            );
                          }}
                          placeholder="Ex. 192.168.1.50"
                          disabled={!canUpdateIncident}
                          className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                        />

                        <div className="mt-2 text-xs text-[var(--muted)]">
                          L’adresse source de l’alerte est utilisée automatiquement lorsqu’elle est disponible.
                        </div>

                        {getSourceIpFromAlert(
                          alert
                        ) && (
                          <div className="mt-2 text-xs text-emerald-400">
                            IP détectée dans l’alerte :{" "}
                            {getSourceIpFromAlert(
                              alert
                            )}
                          </div>
                        )}

                      </div>
                    )}

                    {/* ISOLATE HOST */}

                    {selectedAction ===
                      "ISOLATE_HOST" && (

                      <div>

                        <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                          Hôte à isoler
                        </label>

                        <input
                          value={
                            hostValue
                          }
                          onChange={(e) => {
                            setHostValue(
                              e.target.value
                            );

                            setCible(
                              e.target.value
                            );
                          }}
                          placeholder="IP ou nom de machine"
                          disabled={!canUpdateIncident}
                          className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                        />

                        <div className="mt-2 text-xs text-[var(--muted)]">
                          L’IP de l’agent est utilisée automatiquement lorsqu’elle est disponible.
                        </div>

                        {getAgentIpFromAlert(
                          alert
                        ) && (
                          <div className="mt-2 text-xs text-emerald-400">
                            Hôte détecté :{" "}
                            {getAgentIpFromAlert(
                              alert
                            )}
                          </div>
                        )}

                      </div>
                    )}

                    {/* COLLECT LOGS */}

                    {selectedAction ===
                      "COLLECT_LOGS" && (

                      <div className="rounded-xl border border-blue-400/20 bg-blue-400/5 p-4">

                        <div className="text-sm font-semibold text-blue-400">
                          Collecte ciblée
                        </div>

                        <div className="mt-1 text-xs leading-5 text-[var(--muted)]">
                          Aucun paramètre supplémentaire n’est nécessaire.
                          Les données seront collectées par l’agent Wazuh détecté.
                        </div>

                      </div>
                    )}

                    {/* ADD NOTE */}

                    {selectedAction ===
                      "ADD_NOTE" && (

                      <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-4">

                        <div className="text-sm font-semibold text-[var(--foreground)]">
                          Note d’investigation
                        </div>

                        <div className="mt-1 text-xs text-[var(--muted)]">
                          Une note est obligatoire pour cette action.
                        </div>

                      </div>
                    )}

                    {/* CLOSE INCIDENT */}

                    {selectedAction ===
                      "CLOSE_INCIDENT" && (

                      <div className="rounded-xl border border-yellow-400/20 bg-yellow-400/5 p-4">

                        <div className="text-sm font-semibold text-yellow-400">
                          Clôture de l’incident
                        </div>

                        <div className="mt-1 text-xs text-[var(--muted)]">
                          L’incident sera marqué comme CLOSED.
                          La note ci-dessous permet de documenter la clôture.
                        </div>

                      </div>
                    )}

                    {/* GLPI */}

                    {selectedAction ===
                      "CREATE_GLPI_TICKET" && (

                      <div className="grid grid-cols-1 gap-4">

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            Titre du ticket
                          </label>

                          <input
                            value={
                              glpiTitle
                            }
                            onChange={(e) =>
                              setGlpiTitle(
                                e.target.value
                              )
                            }
                            placeholder="Titre du ticket GLPI"
                            disabled={!canCreateTicket}
                            className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 text-sm text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />
                        </div>

                        <div>
                          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            Description
                          </label>

                          <textarea
                            value={
                              glpiDescription
                            }
                            onChange={(e) =>
                              setGlpiDescription(
                                e.target.value
                              )
                            }
                            rows={5}
                            placeholder="Description du ticket..."
                            disabled={!canCreateTicket}
                            className="w-full resize-none rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 text-sm leading-6 text-[var(--foreground)] outline-none focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                          />
                        </div>

                      </div>
                    )}

                    {/* WAZUH AGENT */}

                    {[
                      "ISOLATE_HOST",
                      "BLOCK_IP",
                      "BLOCK_HASH",
                      "KILL_PROCESS",
                      "COLLECT_LOGS",
                    ].includes(
                      selectedAction
                    ) && (

                      <div>

                        <label className="mb-2 flex items-center justify-between text-xs font-semibold text-[var(--muted)]">

                          <span>
                            WAZUH AGENT
                          </span>

                          <span className="font-normal opacity-60">
                            Détecté automatiquement
                          </span>

                        </label>

                        <input
                          value={
                            agentId
                          }
                          onChange={(e) =>
                            setAgentId(
                              e.target.value
                            )
                          }
                          placeholder="Agent ID"
                          disabled={!canUpdateIncident}
                          className="w-full rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 font-mono text-sm text-[var(--foreground)] outline-none placeholder:text-[var(--muted)]/50 focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                        />

                        {agentId && (
                          <div className="mt-2 flex items-center gap-2 text-xs text-emerald-400">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

                            Agent Wazuh détecté :{" "}
                            {agentId}
                          </div>
                        )}

                      </div>
                    )}

                    {/* NOTE */}

                    {[
                      "ADD_NOTE",
                      "CLOSE_INCIDENT",
                      "BLOCK_HASH",
                      "BLOCK_IP",
                      "ISOLATE_HOST",
                      "KILL_PROCESS",
                      "COLLECT_LOGS",
                    ].includes(
                      selectedAction
                    ) && (

                      <div>

                        <label className="mb-2 block text-xs font-semibold text-[var(--muted)]">
                          JUSTIFICATION / NOTE
                          {selectedAction ===
                            "ADD_NOTE" && (
                            <span className="ml-1 text-[var(--critical)]">
                              *
                            </span>
                          )}
                        </label>

                        <textarea
                          value={
                            note
                          }
                          onChange={(e) =>
                            setNote(
                              e.target.value
                            )
                          }
                          rows={3}
                          placeholder="Décrire brièvement la raison de l’intervention..."
                          disabled={
                            !canUpdateIncident
                          }
                          className="w-full resize-none rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 text-sm leading-6 text-[var(--foreground)] outline-none placeholder:text-[var(--muted)]/50 focus:border-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-60"
                        />

                      </div>
                    )}

                  </div>

                  {/* ACTION FOOTER */}

                  <div className="flex flex-col gap-3 border-t border-[var(--border)] px-5 py-4 sm:flex-row sm:items-center sm:justify-between">

                    <div className="text-xs text-[var(--muted)]">

                      Action sélectionnée :

                      <span className="ml-1 font-mono text-[var(--foreground)]">
                        {selectedAction}
                      </span>

                    </div>

                    <button
                      type="button"
                      onClick={
                        handleResponseAction
                      }
                      disabled={
                        !selectedAction ||
                        !selectedActionAllowed ||
                        submittingAction
                      }
                      className="inline-flex items-center justify-center gap-2 rounded-xl bg-[var(--accent)] px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition-all hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {submittingAction ? (
                        <>
                          <div className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                          Exécution...
                        </>
                      ) : (
                        <>
                          <span>▶</span>
                          Exécuter l’action
                        </>
                      )}
                    </button>

                  </div>

                </div>
              )}

              {/* SUCCESS */}

              {actionMessage && (
                <div className="flex items-start gap-3 rounded-xl border border-emerald-400/30 bg-emerald-400/5 p-4">

                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-400/10 text-emerald-400">
                    ✓
                  </div>

                  <div>
                    <div className="text-sm font-semibold text-emerald-400">
                      Action exécutée
                    </div>

                    <div className="mt-1 text-xs text-[var(--muted)]">
                      {actionMessage}
                    </div>
                  </div>

                </div>
              )}

              {/* ERROR */}

              {actionErrorMsg &&
                catalog.length > 0 && (
                  <div className="flex items-start gap-3 rounded-xl border border-[var(--critical)]/30 bg-[var(--critical)]/5 p-4">

                    <div className="text-[var(--critical)]">
                      ⚠
                    </div>

                    <div>
                      <div className="text-sm font-semibold text-[var(--critical)]">
                        Échec de l’action
                      </div>

                      <div className="mt-1 text-xs text-[var(--muted)]">
                        {actionErrorMsg}
                      </div>
                    </div>

                  </div>
                )}

              {/* =====================================================
                  RESPONSE HISTORY
              ===================================================== */}

              <div className="border-t border-[var(--border)] pt-6">

                <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">

                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                      03 · Response History
                    </div>

                    <div className="mt-1 text-sm text-[var(--foreground)]">
                      Journal des interventions et résultats d’exécution
                    </div>
                  </div>

                  <span className="w-fit rounded-full border border-[var(--border)] bg-white/[0.03] px-3 py-1 text-xs text-[var(--muted)]">
                    {actions.length} action
                    {actions.length !== 1
                      ? "s"
                      : ""}
                  </span>

                </div>

                {actions.length === 0 ? (

                  <div className="rounded-xl border border-dashed border-[var(--border)] bg-white/[0.01] p-6 text-center text-sm text-[var(--muted)]">
                    Aucune intervention enregistrée pour cet incident.
                  </div>

                ) : (

                  <div className="space-y-3">

                    {actions.map(
                      (a) => {

                        const resultat =
                          a?.resultat &&
                          typeof a.resultat ===
                            "object"
                            ? a.resultat
                            : {};

                        const wazuh =
                          resultat?.wazuh ||
                          {};

                        const wazuhResponse =
                          wazuh?.wazuh_response ||
                          {};

                        const wazuhData =
                          wazuhResponse?.data ||
                          {};

                        const agent =
                          wazuh?.agent_id ||
                          a?.parametres
                            ?.agent_id ||
                          null;

                        const command =
                          wazuh?.wazuh_command ||
                          wazuh?.command ||
                          null;

                        const argumentsList =
                          Array.isArray(
                            wazuh?.arguments
                          )
                            ? wazuh.arguments
                            : [];

                        const message =
                          resultat?.message ||
                          resultat?.detail ||
                          resultat?.error ||
                          null;

                        const isFailed =
                          String(
                            a?.statut ||
                              ""
                          ).toUpperCase() ===
                          "FAILED";

                        return (
                          <div
                            key={
                              a.id_action
                            }
                            className="overflow-hidden rounded-xl border border-[var(--border)] bg-white/[0.02] transition-colors hover:bg-white/[0.04]"
                          >

                            <div className="flex flex-col gap-3 border-b border-[var(--border)] p-4 lg:flex-row lg:items-start lg:justify-between">

                              <div className="flex min-w-0 gap-3">

                                <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--accent)]/10 text-sm">
                                  ⚡
                                </div>

                                <div className="min-w-0">

                                  <div className="flex flex-wrap items-center gap-2">

                                    <span className="font-mono text-sm font-semibold text-[var(--foreground)]">
                                      {
                                        a.type_action
                                      }
                                    </span>

                                    <StatusBadge
                                      value={
                                        a.statut
                                      }
                                    />

                                    {a.origine_action && (
                                      <span className="rounded-full border border-[var(--border)] bg-white/[0.03] px-2.5 py-1 text-[10px] font-medium uppercase tracking-wide text-[var(--muted)]">
                                        {
                                          a.origine_action
                                        }
                                      </span>
                                    )}

                                  </div>

                                  <div className="mt-2 text-xs text-[var(--muted)]">
                                    ID :{" "}
                                    <span className="font-mono text-[var(--foreground)]">
                                      {normalizeValue(
                                        a.id_action
                                      )}
                                    </span>
                                  </div>

                                </div>

                              </div>

                              <div className="shrink-0 text-xs text-[var(--muted)]">
                                {formatDate(
                                  a.date_execution
                                )}
                              </div>

                            </div>

                            <div className="grid grid-cols-1 gap-3 p-4 md:grid-cols-2 lg:grid-cols-4">

                              <InfoItem
                                label="Cible"
                                value={
                                  a.cible
                                }
                                mono
                              />

                              <InfoItem
                                label="Agent Wazuh"
                                value={
                                  agent
                                }
                                mono
                              />

                              <InfoItem
                                label="Commande Wazuh"
                                value={
                                  command
                                }
                                mono
                              />

                              <InfoItem
                                label="Mode"
                                value={
                                  wazuh?.mode ||
                                  null
                                }
                              />

                            </div>

                            {argumentsList.length >
                              0 && (
                              <div className="px-4 pb-4">

                                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
                                  Arguments
                                </div>

                                <div className="rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2">
                                  <code className="break-all font-mono text-xs text-[var(--foreground)]">
                                    {JSON.stringify(
                                      argumentsList
                                    )}
                                  </code>
                                </div>

                              </div>
                            )}

                            {a.parametres &&
                              typeof a.parametres ===
                                "object" &&
                              Object.keys(
                                a.parametres
                              ).length >
                                0 && (

                              <div className="px-4 pb-4">

                                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
                                  Paramètres
                                </div>

                                <div className="rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2">
                                  <code className="break-all font-mono text-xs text-[var(--muted)]">
                                    {JSON.stringify(
                                      a.parametres
                                    )}
                                  </code>
                                </div>

                              </div>
                            )}

                            {(message ||
                              a.resultat) && (
                              <div className="border-t border-[var(--border)] px-4 py-4">

                                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[var(--muted)]">
                                  Résultat
                                </div>

                                {message && (
                                  <div
                                    className={`rounded-lg border p-3 text-xs ${
                                      isFailed
                                        ? "border-[var(--critical)]/30 bg-[var(--critical)]/5 text-[var(--critical)]"
                                        : "border-emerald-400/20 bg-emerald-400/5 text-[var(--muted)]"
                                    }`}
                                  >
                                    {message}
                                  </div>
                                )}

                                {wazuhData &&
                                  Object.keys(
                                    wazuhData
                                  ).length >
                                    0 && (
                                    <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">

                                      <div className="rounded-lg border border-[var(--border)] bg-white/[0.02] p-3">

                                        <div className="text-[10px] uppercase tracking-wide text-[var(--muted)]">
                                          Agents affectés
                                        </div>

                                        <div className="mt-1 font-mono text-sm text-[var(--foreground)]">
                                          {Array.isArray(
                                            wazuhData.affected_items
                                          )
                                            ? wazuhData.affected_items.join(
                                                ", "
                                              ) ||
                                              "0"
                                            : normalizeValue(
                                                wazuhData.total_affected_items
                                              )}
                                        </div>

                                      </div>

                                      <div className="rounded-lg border border-[var(--border)] bg-white/[0.02] p-3">

                                        <div className="text-[10px] uppercase tracking-wide text-[var(--muted)]">
                                          Échecs Wazuh
                                        </div>

                                        <div className="mt-1 font-mono text-sm text-[var(--foreground)]">
                                          {normalizeValue(
                                            wazuhData.total_failed_items
                                          )}
                                        </div>

                                      </div>

                                      <div className="rounded-lg border border-[var(--border)] bg-white/[0.02] p-3">

                                        <div className="text-[10px] uppercase tracking-wide text-[var(--muted)]">
                                          Statut Wazuh
                                        </div>

                                        <div className="mt-1 text-sm text-[var(--foreground)]">
                                          {normalizeValue(
                                            wazuh?.status ||
                                              wazuhResponse?.message
                                          )}
                                        </div>

                                      </div>

                                    </div>
                                  )}

                                {isFailed && (
                                  <details className="mt-3">

                                    <summary className="cursor-pointer text-xs text-[var(--muted)] hover:text-[var(--foreground)]">
                                      Afficher les détails techniques
                                    </summary>

                                    <pre className="mt-2 overflow-x-auto rounded-lg border border-[var(--border)] bg-black/20 p-3 font-mono text-[10px] leading-5 text-[var(--muted)]">
                                      {JSON.stringify(
                                        a.resultat,
                                        null,
                                        2
                                      )}
                                    </pre>

                                  </details>
                                )}

                              </div>
                            )}

                          </div>
                        );
                      }
                    )}

                  </div>
                )}

              </div>

            </div>
          )}
        </Section>

        {/* =========================================================
            TRIAGE
        ========================================================= */}

        <Section
          title="Données de triage"
          description="Informations collectées manuellement depuis l’agent Windows via Wazuh Active Response."
        >

          <div className="space-y-5">

            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">

              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
                  COLLECT_LOGS
                </div>

                <div className="mt-1 text-sm text-[var(--foreground)]">
                  Dernières informations disponibles sur l’agent.
                </div>
              </div>

              <button
                type="button"
                onClick={() =>
                  loadCollectedLogs()
                }
                disabled={
                  !canUpdateIncident ||
                  loadingCollectedLogs
                }
                className="inline-flex items-center justify-center gap-2 rounded-lg border border-[var(--border)] bg-white/[0.02] px-4 py-2 text-sm font-medium text-[var(--foreground)] transition-colors hover:bg-white/[0.06] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loadingCollectedLogs ? (
                  <>
                    <div className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
                    Chargement...
                  </>
                ) : (
                  <>
                    ↻
                    Actualiser
                  </>
                )}
              </button>

            </div>

            {collectedLogsError && (
              <div className="rounded-xl border border-[var(--critical)]/30 bg-[var(--critical)]/5 p-4 text-sm text-[var(--critical)]">
                {collectedLogsError}
              </div>
            )}

            {loadingCollectedLogs &&
              !collectedLogs && (
                <div className="flex items-center gap-3 rounded-xl border border-[var(--border)] bg-white/[0.02] p-6 text-sm text-[var(--muted)]">
                  <div className="h-4 w-4 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
                  Récupération des données de triage...
                </div>
              )}

            {!loadingCollectedLogs &&
              collectedLogs &&
              !collectedLogs.found && (
                <div className="rounded-xl border border-yellow-400/20 bg-yellow-400/5 p-5">

                  <div className="text-sm font-semibold text-yellow-400">
                    Aucune donnée de triage disponible
                  </div>

                  <div className="mt-1 text-xs text-[var(--muted)]">
                    {collectedLogs.message ||
                      "Aucune collecte COLLECT_LOGS n’a encore été indexée pour cet agent."}
                  </div>

                  {collectedLogs.agent && (
                    <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">

                      <InfoItem
                        label="Agent"
                        value={
                          collectedLogs.agent?.id
                        }
                        mono
                      />

                      <InfoItem
                        label="Nom"
                        value={
                          collectedLogs.agent?.name
                        }
                      />

                      <InfoItem
                        label="Adresse IP"
                        value={
                          collectedLogs.agent?.ip
                        }
                        mono
                      />

                    </div>
                  )}

                </div>
              )}

            {collectedLogs?.found &&
              collectedLogs?.data && (
                <div className="space-y-6">

                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">

                    <InfoItem
                      label="Machine"
                      value={
                        collectedLogs.data?.computer
                      }
                    />

                    <InfoItem
                      label="Agent Wazuh"
                      value={
                        collectedLogs.agent?.id
                      }
                      mono
                    />

                    <InfoItem
                      label="Adresse IP"
                      value={
                        collectedLogs.agent?.ip
                      }
                      mono
                    />

                    <InfoItem
                      label="Date de collecte"
                      value={formatDate(
                        collectedLogs.data?.timestamp
                      )}
                    />

                  </div>

                  {/* PROCESSUS */}

                  <div>

                    <div className="mb-3 flex items-center justify-between">

                      <div>
                        <div className="text-sm font-semibold text-[var(--foreground)]">
                          Processus
                        </div>

                        <div className="mt-1 text-xs text-[var(--muted)]">
                          Processus observés lors de la collecte.
                        </div>
                      </div>

                      <span className="rounded-full border border-[var(--border)] bg-white/[0.03] px-3 py-1 text-xs text-[var(--muted)]">
                        {collectedLogs.data?.processes?.length || 0}
                      </span>

                    </div>

                    <div className="overflow-x-auto rounded-xl border border-[var(--border)]">

                      <table className="min-w-full text-sm">

                        <thead className="bg-white/[0.03]">
                          <tr>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              PID
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Processus
                            </th>

                          </tr>
                        </thead>

                        <tbody className="divide-y divide-[var(--border)]">

                          {(
                            collectedLogs.data?.processes ||
                            []
                          ).length === 0 ? (

                            <tr>
                              <td
                                colSpan={2}
                                className="px-4 py-5 text-center text-xs text-[var(--muted)]"
                              >
                                Aucun processus disponible.
                              </td>
                            </tr>

                          ) : (

                            (
                              collectedLogs.data?.processes ||
                              []
                            ).map(
                              (
                                process,
                                index
                              ) => (
                                <tr
                                  key={`${process?.Id || "process"}-${index}`}
                                  className="transition-colors hover:bg-white/[0.02]"
                                >

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      process?.Id
                                    )}
                                  </td>

                                  <td className="px-4 py-3 font-medium text-[var(--foreground)]">
                                    {normalizeValue(
                                      process?.ProcessName
                                    )}
                                  </td>

                                </tr>
                              )
                            )
                          )}

                        </tbody>

                      </table>

                    </div>

                  </div>

                  {/* NETWORK */}

                  <div>

                    <div className="mb-3 flex items-center justify-between">

                      <div>
                        <div className="text-sm font-semibold text-[var(--foreground)]">
                          Connexions réseau
                        </div>

                        <div className="mt-1 text-xs text-[var(--muted)]">
                          Connexions TCP établies au moment de la collecte.
                        </div>
                      </div>

                      <span className="rounded-full border border-[var(--border)] bg-white/[0.03] px-3 py-1 text-xs text-[var(--muted)]">
                        {collectedLogs.data?.network_connections?.length || 0}
                      </span>

                    </div>

                    <div className="overflow-x-auto rounded-xl border border-[var(--border)]">

                      <table className="min-w-full text-sm">

                        <thead className="bg-white/[0.03]">
                          <tr>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Adresse locale
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Port local
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Adresse distante
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Port distant
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              PID
                            </th>

                          </tr>
                        </thead>

                        <tbody className="divide-y divide-[var(--border)]">

                          {(
                            collectedLogs.data?.network_connections ||
                            []
                          ).length === 0 ? (

                            <tr>
                              <td
                                colSpan={5}
                                className="px-4 py-5 text-center text-xs text-[var(--muted)]"
                              >
                                Aucune connexion réseau disponible.
                              </td>
                            </tr>

                          ) : (

                            (
                              collectedLogs.data?.network_connections ||
                              []
                            ).map(
                              (
                                connection,
                                index
                              ) => (
                                <tr
                                  key={`${connection?.LocalAddress || "connection"}-${connection?.LocalPort || index}-${index}`}
                                  className="transition-colors hover:bg-white/[0.02]"
                                >

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      connection?.LocalAddress
                                    )}
                                  </td>

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      connection?.LocalPort
                                    )}
                                  </td>

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      connection?.RemoteAddress
                                    )}
                                  </td>

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      connection?.RemotePort
                                    )}
                                  </td>

                                  <td className="px-4 py-3 font-mono text-xs text-[var(--foreground)]">
                                    {normalizeValue(
                                      connection?.OwningProcess
                                    )}
                                  </td>

                                </tr>
                              )
                            )
                          )}

                        </tbody>

                      </table>

                    </div>

                  </div>

                  {/* SERVICES */}

                  <div>

                    <div className="mb-3 flex items-center justify-between">

                      <div>
                        <div className="text-sm font-semibold text-[var(--foreground)]">
                          Services actifs
                        </div>

                        <div className="mt-1 text-xs text-[var(--muted)]">
                          Services Windows en cours d’exécution lors de la collecte.
                        </div>
                      </div>

                      <span className="rounded-full border border-[var(--border)] bg-white/[0.03] px-3 py-1 text-xs text-[var(--muted)]">
                        {collectedLogs.data?.running_services?.length || 0}
                      </span>

                    </div>

                    <div className="overflow-x-auto rounded-xl border border-[var(--border)]">

                      <table className="min-w-full text-sm">

                        <thead className="bg-white/[0.03]">
                          <tr>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Nom
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Description
                            </th>

                            <th className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                              Statut
                            </th>

                          </tr>
                        </thead>

                        <tbody className="divide-y divide-[var(--border)]">

                          {(
                            collectedLogs.data?.running_services ||
                            []
                          ).length === 0 ? (

                            <tr>
                              <td
                                colSpan={3}
                                className="px-4 py-5 text-center text-xs text-[var(--muted)]"
                              >
                                Aucun service disponible.
                              </td>
                            </tr>

                          ) : (

                            (
                              collectedLogs.data?.running_services ||
                              []
                            ).map(
                              (
                                service,
                                index
                              ) => (
                                <tr
                                  key={`${service?.Name || "service"}-${index}`}
                                  className="transition-colors hover:bg-white/[0.02]"
                                >

                                  <td className="px-4 py-3 font-medium text-[var(--foreground)]">
                                    {normalizeValue(
                                      service?.Name
                                    )}
                                  </td>

                                  <td className="px-4 py-3 text-xs text-[var(--muted)]">
                                    {normalizeValue(
                                      service?.DisplayName
                                    )}
                                  </td>

                                  <td className="px-4 py-3">

                                    <span className="inline-flex rounded-full border border-emerald-400/20 bg-emerald-400/5 px-2.5 py-1 text-xs font-medium text-emerald-400">
                                      {normalizeValue(
                                        service?.Status ||
                                          "Running"
                                      )}
                                    </span>

                                  </td>

                                </tr>
                              )
                            )
                          )}

                        </tbody>

                      </table>

                    </div>

                  </div>

                </div>
              )}

          </div>
        </Section>

        {/* =========================================================
            THEHIVE
        ========================================================= */}

        <Section
          title="TheHive"
          description="État de la prise en charge de l’incident dans TheHive."
        >
          {theHiveId ? (

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

              <InfoItem
                label="Case TheHive"
                value={theHiveId}
                mono
              />

              <InfoItem
                label="État"
                value="Case associée"
              />

            </div>

          ) : (

            <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-5 text-sm text-[var(--muted)]">
              Aucun Case TheHive associé à cet incident.
            </div>

          )}
        </Section>

        {/* =========================================================
            ALERT ORIGIN
        ========================================================= */}

        <Section
          title="Alerte d’origine"
          description="Alerte de sécurité ayant conduit à la création de cet incident."
        >

          {loadingAlert ? (

            <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-5 text-sm text-[var(--muted)]">
              Chargement de l’alerte...
            </div>

          ) : alertError ? (

            <div className="rounded-xl border border-[var(--critical)]/40 bg-[var(--critical)]/5 p-5 text-sm text-[var(--critical)]">
              {alertError}
            </div>

          ) : alert ? (

            <div className="space-y-5">

              <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">

                <InfoItem
                  label="ID alerte"
                  value={
                    alert.id_alerte ||
                    alertId
                  }
                  mono
                />

                <InfoItem
                  label="Titre"
                  value={alert.titre}
                />

                <InfoItem
                  label="Source"
                  value={
                    alert.source_alerte
                  }
                />

                <InfoItem
                  label="Sévérité"
                  value={
                    alert.severite
                  }
                />

                <InfoItem
                  label="Identifiant externe"
                  value={
                    alert.identifiant_externe
                  }
                  mono
                />

                <InfoItem
                  label="Date de création"
                  value={formatDate(
                    alert.date_creation
                  )}
                />

              </div>

              <div>

                <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                  Description
                </div>

                <div className="whitespace-pre-wrap rounded-xl border border-[var(--border)] bg-black/5 p-5 text-sm leading-7 text-[var(--foreground)]">
                  {normalizeValue(
                    alert.description
                  )}
                </div>

              </div>

              {canReadAlert && (
                <button
                  type="button"
                  onClick={() =>
                    router.push(
                      `/alerts/${
                        alert.id_alerte ||
                        alertId
                      }`
                    )
                  }
                  className="rounded-lg border border-[var(--border)] bg-white/[0.02] px-4 py-2.5 text-sm font-medium transition-colors hover:bg-white/[0.06]"
                >
                  Ouvrir l’alerte complète
                </button>
              )}

            </div>

          ) : (

            <div className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-5 text-sm text-[var(--muted)]">
              Aucune alerte associée.
            </div>

          )}

        </Section>

      </div>
    </main>
  );
}

