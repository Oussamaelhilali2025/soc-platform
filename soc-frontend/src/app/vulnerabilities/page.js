"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Play,
  RefreshCw,
  Search,
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
  ArrowLeft,
  Server,
  Ticket,
  Eye,
  EyeOff,
  Activity,
  ShieldAlert,
  AlertCircle,
  Info,
} from "lucide-react";

import { apiFetch } from "@/lib/api";
import { useRBAC } from "@/components/auth/RBACContext";

const scanProfiles = [
  { value: "full_fast", label: "Full and Fast" },
  { value: "full", label: "Full and Very Deep" },
  { value: "discovery", label: "Host Discovery" },
];

export default function VulnerabilitiesPage() {
  /* =====================================================
     RBAC
  ===================================================== */

  const {
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadAssets = hasPermission("ASSET_READ");
  const canCreateScan = hasPermission("SCAN_CREATE");
  const canCreateTicket = hasPermission("TICKET_CREATE");

  /* =====================================================
     ÉTATS
  ===================================================== */

  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("full_fast");

  const [scans, setScans] = useState([]);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  const [selectedHost, setSelectedHost] = useState("ALL");
  const [expandedVulnerability, setExpandedVulnerability] =
    useState(null);

  const [loading, setLoading] = useState(false);
  const [loadingScans, setLoadingScans] = useState(true);
  const [loadingVulnerabilities, setLoadingVulnerabilities] =
    useState(true);
  const [creatingTicketId, setCreatingTicketId] = useState(null);

  const [error, setError] = useState("");

  /* =====================================================
     CHARGEMENT DES VULNÉRABILITÉS
  ===================================================== */

  async function loadVulnerabilities() {
    if (!canReadAssets) {
      return;
    }

    try {
      setLoadingVulnerabilities(true);

      const data = await apiFetch("/resultat-vulnerabilite");

      const resultList = Array.isArray(data)
        ? data
        : data.results || [];

      const normalized = resultList.map((item) => ({
        id: item.id_resultat,

        severity: String(
          item.severite ||
            item.vulnerabilite_severite ||
            "UNKNOWN"
        )
          .trim()
          .toUpperCase(),

        cvss:
          item.score_cvss ??
          item.vulnerabilite_score_cvss ??
          null,

        cve: item.cve || null,

        name:
          item.vulnerabilite_nom ||
          "Vulnérabilité inconnue",

        description:
          item.vulnerabilite_description || "",

        host:
          item.actif_ip ||
          item.scan_cible ||
          "-",

        asset:
          item.actif_nom ||
          "-",

        hostname:
          item.actif_hostname ||
          "-",

        port: item.port ?? "-",

        protocol:
          item.protocole ||
          "-",

        proof:
          item.preuve ||
          "",

        solution:
          item.solution ||
          "",

        status:
          item.statut ||
          "DETECTED",

        vulnerabilityStatus:
          item.vulnerabilite_statut ||
          "OPEN",

        scan:
          item.scan_nom ||
          "-",

        detectedAt:
          item.date_detection ||
          null,
      }));

      setVulnerabilities(normalized);
    } catch (err) {
      console.error(
        "Erreur chargement vulnérabilités:",
        err
      );

      if (err.message !== "Session expirée.") {
        setError(
          err.message ||
            "Impossible de récupérer les vulnérabilités"
        );
      }

      setVulnerabilities([]);
    } finally {
      setLoadingVulnerabilities(false);
    }
  }

  /* =====================================================
     CHARGEMENT DES SCANS
  ===================================================== */

  async function loadScans() {
    if (!canReadAssets) {
      return;
    }

    try {
      setLoadingScans(true);
      setError("");

      const data = await apiFetch(
        "/vulnerability/scans"
      );

      const scanList = Array.isArray(data)
        ? data
        : data.scans || [];

      const enrichedScans = await Promise.all(
        scanList.map(async (scan) => {
          const taskId =
            scan.identificateur_externe_openvas ||
            scan.task_id;

          if (!taskId) {
            return {
              ...scan,
              task_id: null,
              target: scan.cible || "-",
              status:
                scan.statut ||
                "UNKNOWN",
              progress: 0,
              profile:
                extractProfile(
                  scan.description
                ) || "full_fast",
            };
          }

          try {
            const statusData =
              await apiFetch(
                `/scan_vulnerabilite/${taskId}/status`
              );

            const greenboneStatus =
              String(
                statusData.statut || ""
              ).toLowerCase();

            let progress = Number(
              statusData.progress
            );

            if (
              greenboneStatus === "done" ||
              greenboneStatus === "finished" ||
              greenboneStatus === "completed"
            ) {
              progress = 100;
            } else if (
              !Number.isFinite(progress) ||
              progress < 0
            ) {
              progress = 0;
            }

            return {
              ...scan,
              task_id: taskId,
              target:
                scan.cible || "-",
              profile:
                extractProfile(
                  scan.description
                ) || "full_fast",
              status:
                statusData.statut ||
                scan.statut ||
                "UNKNOWN",
              progress,
            };
          } catch (statusError) {
            console.error(
              `Erreur statut scan ${taskId}:`,
              statusError
            );

            return {
              ...scan,
              task_id: taskId,
              target:
                scan.cible || "-",
              profile:
                extractProfile(
                  scan.description
                ) || "full_fast",
              status:
                scan.statut ||
                "UNKNOWN",
              progress: 0,
            };
          }
        })
      );

      setScans(enrichedScans);
    } catch (err) {
      console.error(err);

      if (err.message !== "Session expirée.") {
        setError(
          err.message ||
            "Impossible de récupérer les scans"
        );
      }

      setScans([]);
    } finally {
      setLoadingScans(false);
    }
  }

  /* =====================================================
     CHARGEMENT GLOBAL
  ===================================================== */

  async function loadData() {
    if (!canReadAssets) {
      return;
    }

    await Promise.all([
      loadScans(),
      loadVulnerabilities(),
    ]);
  }

  /* =====================================================
     LANCEMENT SCAN
  ===================================================== */

  async function launchScan(event) {
    event.preventDefault();

    if (!canCreateScan) {
      setError(
        "Votre compte ne possède pas la permission nécessaire pour lancer un scan."
      );
      return;
    }

    if (!target.trim()) {
      setError(
        "Veuillez saisir une cible."
      );
      return;
    }

    try {
      setLoading(true);
      setError("");

      const data = await apiFetch(
        "/vulnerability/scan",
        {
          method: "POST",
          body: JSON.stringify({
            target: target.trim(),
            profile,
          }),
        }
      );

      console.log(
        "Scan Greenbone lancé:",
        data
      );

      setTarget("");

      await loadScans();
    } catch (err) {
      console.error(err);

      setError(
        err.message ||
          "Impossible de lancer le scan"
      );
    } finally {
      setLoading(false);
    }
  }

  /* =====================================================
     CRÉATION TICKET GLPI
  ===================================================== */

  async function handleCreateGlpiTicket(
    vulnerability
  ) {
    if (!canCreateTicket) {
      setError(
        "Votre compte ne possède pas la permission nécessaire pour créer un ticket GLPI."
      );
      return;
    }

    if (vulnerability?.id == null) {
      setError(
        "Impossible d'identifier la vulnérabilité."
      );
      return;
    }

    try {
      setCreatingTicketId(
        vulnerability.id
      );

      setError("");

      const port =
        vulnerability.port !== "-" &&
        vulnerability.port != null
          ? `${vulnerability.port}/${
              vulnerability.protocol || "-"
            }`
          : "-";

      const severity = String(
        vulnerability.severity || "LOW"
      )
        .trim()
        .toUpperCase();

      const urgencyMap = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
      };

      const urgency =
        urgencyMap[severity] ?? 2;

      const content = [
        "VULNÉRABILITÉ GREENBONE",
        "",

        "==============================",
        "ACTIF",
        "==============================",

        `Nom : ${
          vulnerability.asset || "-"
        }`,

        `Adresse IP : ${
          vulnerability.host || "-"
        }`,

        `Hostname : ${
          vulnerability.hostname || "-"
        }`,

        "",

        "==============================",
        "VULNÉRABILITÉ",
        "==============================",

        `Nom : ${
          vulnerability.name || "-"
        }`,

        `Sévérité : ${severity}`,

        `CVSS : ${
          vulnerability.cvss ?? "-"
        }`,

        `CVE : ${
          vulnerability.cve || "-"
        }`,

        `Port : ${port}`,

        `Statut du résultat : ${
          vulnerability.status || "-"
        }`,

        `Statut vulnérabilité : ${
          vulnerability.vulnerabilityStatus ||
          "-"
        }`,

        `Date de détection : ${formatDate(
          vulnerability.detectedAt
        )}`,

        "",

        "==============================",
        "DESCRIPTION",
        "==============================",

        vulnerability.description ||
          "Aucune description disponible.",

        "",

        "==============================",
        "PREUVE",
        "==============================",

        vulnerability.proof ||
          "Aucune preuve fournie par Greenbone.",

        "",

        "==============================",
        "SOLUTION / REMÉDIATION",
        "==============================",

        vulnerability.solution ||
          "Aucune solution fournie par Greenbone.",

        "",

        "==============================",
        "SOURCE",
        "==============================",

        "Greenbone / OpenVAS",
      ].join("\n");

      const data = await apiFetch(
        "/glpi/tickets",
        {
          method: "POST",

          body: JSON.stringify({
            name: `[Greenbone] ${
              vulnerability.name ||
              "Vulnérabilité détectée"
            }`,

            content,

            urgency,

            id_resultat:
              vulnerability.id,
          }),
        }
      );

      console.log(
        "Ticket GLPI créé :",
        data
      );

      const ticketId =
        data?.ticket?.id;

      if (ticketId != null) {
        alert(
          `Ticket GLPI #${ticketId} créé avec succès.`
        );
      } else {
        alert(
          "Ticket GLPI créé avec succès."
        );
      }

      await loadVulnerabilities();
    } catch (err) {
      console.error(
        "Erreur création ticket GLPI :",
        err
      );

      if (
        err.message !==
        "Session expirée."
      ) {
        setError(
          err.message ||
            "Impossible de créer le ticket GLPI."
        );
      }
    } finally {
      setCreatingTicketId(null);
    }
  }

  /* =====================================================
     INITIALISATION + AUTO REFRESH
  ===================================================== */

  useEffect(() => {
    if (rbacLoading || !canReadAssets) {
      return;
    }

    loadData();

    const interval =
      setInterval(() => {
        loadData();
      }, 10000);

    return () =>
      clearInterval(interval);
  }, [
    rbacLoading,
    canReadAssets,
  ]);

  /* =====================================================
     LISTE DES ACTIFS
  ===================================================== */

  const hosts = useMemo(() => {
    const map = new Map();

    vulnerabilities.forEach(
      (vuln) => {
        const host =
          vuln.host || "-";

        if (!map.has(host)) {
          map.set(host, {
            host,
            asset:
              vuln.asset || "-",
            hostname:
              vuln.hostname || "-",
            vulnerabilities: 0,
          });
        }

        map.get(
          host
        ).vulnerabilities += 1;
      }
    );

    scans.forEach((scan) => {
      const host =
        scan.target ||
        scan.cible;

      if (
        !host ||
        host === "-"
      ) {
        return;
      }

      if (!map.has(host)) {
        map.set(host, {
          host,
          asset: "-",
          hostname: "-",
          vulnerabilities: 0,
        });
      }
    });

    return Array.from(
      map.values()
    ).sort((a, b) =>
      a.host.localeCompare(
        b.host
      )
    );
  }, [
    vulnerabilities,
    scans,
  ]);

  /* =====================================================
     FILTRES
  ===================================================== */

  const filteredVulnerabilities =
    useMemo(() => {
      if (
        selectedHost === "ALL"
      ) {
        return vulnerabilities;
      }

      return vulnerabilities.filter(
        (vuln) =>
          vuln.host ===
          selectedHost
      );
    }, [
      vulnerabilities,
      selectedHost,
    ]);

  const filteredScans =
    useMemo(() => {
      if (
        selectedHost === "ALL"
      ) {
        return scans;
      }

      return scans.filter(
        (scan) =>
          (
            scan.target ||
            scan.cible ||
            "-"
          ) === selectedHost
      );
    }, [
      scans,
      selectedHost,
    ]);

  /* =====================================================
     STATISTIQUES
  ===================================================== */

  const totalVulnerabilities =
    filteredVulnerabilities.length;

  const criticalCount =
    filteredVulnerabilities.filter(
      (v) =>
        v.severity ===
        "CRITICAL"
    ).length;

  const highCount =
    filteredVulnerabilities.filter(
      (v) =>
        v.severity ===
        "HIGH"
    ).length;

  const mediumCount =
    filteredVulnerabilities.filter(
      (v) =>
        v.severity ===
        "MEDIUM"
    ).length;

  const lowCount =
    filteredVulnerabilities.filter(
      (v) =>
        v.severity ===
        "LOW"
    ).length;

  /* =====================================================
     DÉTAILS
  ===================================================== */

  function toggleDetails(id) {
    setExpandedVulnerability(
      (current) =>
        current === id
          ? null
          : id
    );
  }

  /* =====================================================
     RBAC LOADING
  ===================================================== */

  if (rbacLoading) {
    return (
      <div className="min-h-screen bg-slate-950 text-white">
        <div className="flex min-h-screen items-center justify-center">
          <div className="flex items-center gap-3 text-sm text-slate-400">
            <RefreshCw className="h-5 w-5 animate-spin text-cyan-400" />
            Vérification des permissions...
          </div>
        </div>
      </div>
    );
  }

  /* =====================================================
     RBAC ACCESS DENIED
  ===================================================== */

  if (!canReadAssets) {
    return (
      <div className="min-h-screen bg-slate-950 text-white">
        <div className="mx-auto flex min-h-screen max-w-2xl items-center justify-center p-6">
          <div className="w-full rounded-2xl border border-red-500/30 bg-red-950/20 p-6">
            <div className="flex items-start gap-3">
              <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />

              <div>
                <div className="text-sm font-semibold text-red-400">
                  Accès refusé
                </div>

                <p className="mt-2 text-sm leading-relaxed text-slate-400">
                  Votre compte ne possède pas la permission
                  nécessaire pour consulter les vulnérabilités
                  et les actifs.
                </p>

                <Link
                  href="/dashboard"
                  className="mt-5 inline-flex items-center gap-2 rounded-lg border border-slate-700/80 bg-slate-900 px-4 py-2 text-sm font-medium text-slate-300 transition hover:bg-slate-800 hover:text-white"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Retour au Dashboard
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  /* =====================================================
     RENDER
  ===================================================== */

  return (
    <div className="min-h-screen bg-slate-950">
      <div className="mx-auto max-w-[1600px] space-y-6 p-4 md:p-6 lg:p-8">

        {/* HEADER */}

        <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <Link
              href="/dashboard"
              className="mb-3 inline-flex items-center gap-1.5 text-sm text-slate-500 transition-colors hover:text-cyan-400"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Retour au Dashboard
            </Link>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 ring-1 ring-cyan-500/20">
                <ShieldCheck className="h-5 w-5 text-cyan-400" />
              </div>

              <div>
                <h1 className="text-2xl font-semibold tracking-tight text-white">
                  Vulnérabilités
                </h1>

                <p className="mt-0.5 text-sm text-slate-400">
                  Analyse et suivi des actifs • Greenbone / OpenVAS
                </p>
              </div>
            </div>
          </div>

          <button
            onClick={loadData}
            disabled={
              loadingScans ||
              loadingVulnerabilities
            }
            className="inline-flex items-center justify-center gap-2 self-start rounded-lg border border-slate-700/80 bg-slate-900/80 px-4 py-2 text-sm font-medium text-slate-200 shadow-sm transition hover:border-slate-600 hover:bg-slate-800 disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${
                loadingScans ||
                loadingVulnerabilities
                  ? "animate-spin"
                  : ""
              }`}
            />

            Actualiser
          </button>
        </div>

        {/* ERROR */}

        {error && (
          <div className="flex items-start gap-3 rounded-xl border border-red-500/20 bg-red-950/40 px-4 py-3.5 text-sm text-red-300">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />

            <span>{error}</span>
          </div>
        )}

        {/* NOUVEAU SCAN */}

        <section className="overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/40 shadow-xl shadow-black/20">
          <div className="border-b border-slate-800/80 bg-slate-900/60 px-5 py-4">
            <h2 className="text-base font-semibold text-white">
              Nouveau scan
            </h2>

            <p className="mt-0.5 text-sm text-slate-400">
              Lancez une analyse de vulnérabilités sur un actif
            </p>
          </div>

          <form
            onSubmit={launchScan}
            className="grid grid-cols-1 gap-4 p-5 lg:grid-cols-[1fr_240px_auto]"
          >
            <div className="space-y-1.5">
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-500">
                Cible
              </label>

              <input
                type="text"
                value={target}
                onChange={(e) =>
                  setTarget(
                    e.target.value
                  )
                }
                disabled={!canCreateScan}
                placeholder="Ex. 192.168.1.10"
                className="w-full rounded-lg border border-slate-700/80 bg-slate-950/80 px-3.5 py-2.5 text-sm text-white placeholder:text-slate-600 outline-none transition focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
              />
            </div>

            <div className="space-y-1.5">
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-500">
                Profil de scan
              </label>

              <select
                value={profile}
                onChange={(e) =>
                  setProfile(
                    e.target.value
                  )
                }
                disabled={!canCreateScan}
                className="w-full rounded-lg border border-slate-700/80 bg-slate-950/80 px-3.5 py-2.5 text-sm text-white outline-none transition focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {scanProfiles.map(
                  (item) => (
                    <option
                      key={
                        item.value
                      }
                      value={
                        item.value
                      }
                    >
                      {item.label}
                    </option>
                  )
                )}
              </select>
            </div>

            <div className="flex items-end">
              <button
                type="submit"
                disabled={
                  loading ||
                  !canCreateScan
                }
                title={
                  !canCreateScan
                    ? "Permission SCAN_CREATE requise"
                    : undefined
                }
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-cyan-900/30 transition hover:bg-cyan-500 disabled:cursor-not-allowed disabled:opacity-50 lg:w-auto"
              >
                <Play className="h-4 w-4" />

                {loading
                  ? "Lancement..."
                  : "Lancer le scan"}
              </button>
            </div>
          </form>

          {!canCreateScan && (
            <div className="border-t border-slate-800/80 bg-slate-950/30 px-5 py-3 text-xs text-slate-500">
              La consultation des vulnérabilités est autorisée,
              mais votre rôle ne permet pas de lancer un nouveau
              scan.
            </div>
          )}
        </section>

        {/* MACHINES */}

        <section className="overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/40 shadow-xl shadow-black/20">
          <div className="flex flex-col gap-3 border-b border-slate-800/80 bg-slate-900/60 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-white">
                Machines / Actifs
              </h2>

              <p className="mt-0.5 text-sm text-slate-400">
                Filtrez les analyses et vulnérabilités par machine
              </p>
            </div>

            <span className="inline-flex items-center rounded-full bg-slate-800/80 px-3 py-1 text-xs font-medium text-slate-300 ring-1 ring-slate-700/50">
              {hosts.length} actif
              {hosts.length !== 1
                ? "s"
                : ""}
            </span>
          </div>

          <div className="flex flex-wrap gap-2 p-4">
            <button
              onClick={() =>
                setSelectedHost(
                  "ALL"
                )
              }
              className={`inline-flex items-center gap-2 rounded-xl border px-3.5 py-2 text-sm font-medium transition ${
                selectedHost ===
                "ALL"
                  ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-900/20"
                  : "border-slate-700/60 bg-slate-900/60 text-slate-400 hover:border-slate-600 hover:bg-slate-800/60 hover:text-slate-200"
              }`}
            >
              <Server className="h-4 w-4" />
              Tous les actifs
            </button>

            {hosts.map(
              (host) => (
                <button
                  key={host.host}
                  onClick={() =>
                    setSelectedHost(
                      host.host
                    )
                  }
                  className={`inline-flex items-center gap-2.5 rounded-xl border px-3.5 py-2 text-left transition ${
                    selectedHost ===
                    host.host
                      ? "border-cyan-500/40 bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-900/20"
                      : "border-slate-700/60 bg-slate-900/60 text-slate-400 hover:border-slate-600 hover:bg-slate-800/60 hover:text-slate-200"
                  }`}
                >
                  <Server className="h-4 w-4 shrink-0 opacity-70" />

                  <span>
                    <span className="block text-sm font-medium">
                      {host.asset !==
                      "-"
                        ? host.asset
                        : host.host}
                    </span>

                    <span className="block text-[11px] opacity-70">
                      {host.host} ·{" "}
                      {
                        host.vulnerabilities
                      }{" "}
                      vuln.
                    </span>
                  </span>
                </button>
              )
            )}

            {hosts.length ===
              0 && (
              <div className="w-full py-10 text-center text-sm text-slate-500">
                Aucun actif n&apos;est encore disponible.
              </div>
            )}
          </div>
        </section>

        {/* STATISTIQUES */}

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatCard
            label="Total"
            value={
              totalVulnerabilities
            }
            icon={Activity}
            color="slate"
          />

          <StatCard
            label="Critical"
            value={criticalCount}
            icon={ShieldAlert}
            color="red"
          />

          <StatCard
            label="High"
            value={highCount}
            icon={AlertCircle}
            color="orange"
          />

          <StatCard
            label="Medium"
            value={mediumCount}
            icon={AlertTriangle}
            color="yellow"
          />

          <StatCard
            label="Low"
            value={lowCount}
            icon={Info}
            color="blue"
          />
        </div>

        {/* HISTORIQUE SCANS */}

        <section className="overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/40 shadow-xl shadow-black/20">
          <div className="flex flex-col gap-3 border-b border-slate-800/80 bg-slate-900/60 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-white">
                Historique des scans
              </h2>

              <p className="mt-0.5 text-sm text-slate-400">
                {selectedHost ===
                "ALL"
                  ? "Historique global des analyses Greenbone"
                  : `Analyses de ${selectedHost}`}
              </p>
            </div>

            <span className="inline-flex items-center rounded-full bg-slate-800/80 px-3 py-1 text-xs font-medium text-slate-300 ring-1 ring-slate-700/50">
              {
                filteredScans.length
              }{" "}
              scan
              {filteredScans.length !==
              1
                ? "s"
                : ""}
            </span>
          </div>

          {loadingScans ? (
            <LoadingState text="Chargement des scans..." />
          ) : filteredScans.length ===
            0 ? (
            <EmptyState
              icon={Search}
              text="Aucun scan pour cette machine."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800/80 text-[11px] uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-3.5 font-medium">
                      Cible
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Profil
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Statut
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Progression
                    </th>

                    <th className="px-5 py-3.5 font-medium text-right">
                      Vulnérabilités
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800/60">
                  {filteredScans.map(
                    (scan) => {
                      const progress =
                        Math.min(
                          100,
                          Math.max(
                            0,
                            Number(
                              scan.progress
                            ) || 0
                          )
                        );

                      const scanTarget =
                        scan.target ||
                        scan.cible ||
                        "-";

                      const scanVulnerabilities =
                        vulnerabilities.filter(
                          (vuln) =>
                            vuln.host ===
                            scanTarget
                        ).length;

                      return (
                        <tr
                          key={
                            scan.task_id ||
                            scan.identificateur_externe_openvas ||
                            scan.id_scan ||
                            scan.id
                          }
                          className="group transition-colors hover:bg-slate-800/30"
                        >
                          <td className="px-5 py-4">
                            <div className="font-medium text-slate-200">
                              {
                                scanTarget
                              }
                            </div>

                            <div className="mt-0.5 font-mono text-[11px] text-slate-600">
                              {scan.task_id ||
                                "—"}
                            </div>
                          </td>

                          <td className="px-5 py-4">
                            <span className="rounded-md bg-slate-800/80 px-2 py-1 text-xs text-slate-300">
                              {scan.profile ||
                                "full_fast"}
                            </span>
                          </td>

                          <td className="px-5 py-4">
                            <StatusBadge
                              status={
                                scan.status
                              }
                            />
                          </td>

                          <td className="px-5 py-4">
                            <div className="flex items-center gap-3">
                              <div className="h-1.5 w-28 overflow-hidden rounded-full bg-slate-800">
                                <div
                                  className="h-full rounded-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all duration-700"
                                  style={{
                                    width: `${progress}%`,
                                  }}
                                />
                              </div>

                              <span className="min-w-[2.5rem] text-xs font-medium tabular-nums text-slate-400">
                                {
                                  progress
                                }
                                %
                              </span>
                            </div>
                          </td>

                          <td className="px-5 py-4 text-right">
                            <span className="inline-flex min-w-[2rem] justify-center rounded-full bg-slate-800/80 px-2.5 py-1 text-xs font-medium tabular-nums text-slate-300">
                              {
                                scanVulnerabilities
                              }
                            </span>
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* VULNÉRABILITÉS */}

        <section className="overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/40 shadow-xl shadow-black/20">
          <div className="flex flex-col gap-3 border-b border-slate-800/80 bg-slate-900/60 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-base font-semibold text-white">
                Vulnérabilités détectées
              </h2>

              <p className="mt-0.5 text-sm text-slate-400">
                {selectedHost ===
                "ALL"
                  ? "Résultats issus des rapports Greenbone"
                  : `Vulnérabilités détectées sur ${selectedHost}`}
              </p>
            </div>

            <span className="inline-flex items-center rounded-full bg-slate-800/80 px-3 py-1 text-xs font-medium text-slate-300 ring-1 ring-slate-700/50">
              {
                totalVulnerabilities
              }{" "}
              détectée
              {totalVulnerabilities !==
              1
                ? "s"
                : ""}
            </span>
          </div>

          {loadingVulnerabilities ? (
            <LoadingState text="Chargement des vulnérabilités..." />
          ) : filteredVulnerabilities.length ===
            0 ? (
            <EmptyState
              icon={ShieldCheck}
              text="Aucune vulnérabilité détectée pour cette machine."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800/80 text-[11px] uppercase tracking-wider text-slate-500">
                    <th className="px-5 py-3.5 font-medium">
                      Sévérité
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Vulnérabilité
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      CVSS
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Actif
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Port
                    </th>

                    <th className="px-5 py-3.5 font-medium">
                      Statut
                    </th>

                    <th className="px-5 py-3.5 font-medium text-right">
                      Actions
                    </th>
                  </tr>
                </thead>

                <tbody className="divide-y divide-slate-800/60">
                  {filteredVulnerabilities.map(
                    (vuln) => {
                      const expanded =
                        expandedVulnerability ===
                        vuln.id;

                      return (
                        <tr
                          key={
                            vuln.id
                          }
                          className={`group transition-colors ${
                            expanded
                              ? "bg-slate-800/40"
                              : "hover:bg-slate-800/30"
                          }`}
                        >
                          <td className="px-5 py-4 align-top">
                            <SeverityBadge
                              severity={
                                vuln.severity
                              }
                            />
                          </td>

                          <td className="max-w-xs px-5 py-4 align-top">
                            <div className="font-medium leading-snug text-slate-200">
                              {
                                vuln.name
                              }
                            </div>

                            {vuln.cve && (
                              <div className="mt-1 font-mono text-xs text-cyan-400/90">
                                {
                                  vuln.cve
                                }
                              </div>
                            )}
                          </td>

                          <td className="px-5 py-4 align-top">
                            <span className="font-semibold tabular-nums text-slate-200">
                              {
                                vuln.cvss ??
                                "—"
                              }
                            </span>
                          </td>

                          <td className="px-5 py-4 align-top">
                            <div className="text-slate-200">
                              {
                                vuln.asset
                              }
                            </div>

                            <div className="mt-0.5 text-xs text-slate-500">
                              {
                                vuln.host
                              }
                            </div>

                            {vuln.hostname !==
                              "-" && (
                              <div className="mt-0.5 text-[11px] text-slate-600">
                                {
                                  vuln.hostname
                                }
                              </div>
                            )}
                          </td>

                          <td className="px-5 py-4 align-top text-slate-400">
                            {vuln.port !==
                            "-"
                              ? `${vuln.port}/${vuln.protocol}`
                              : "—"}
                          </td>

                          <td className="px-5 py-4 align-top">
                            <div className="flex flex-col gap-1">
                              <span className="inline-flex w-fit rounded-full bg-red-500/10 px-2 py-0.5 text-[11px] font-medium text-red-400 ring-1 ring-red-500/20">
                                {
                                  vuln.status
                                }
                              </span>

                              <span className="text-[11px] text-slate-500">
                                {
                                  vuln.vulnerabilityStatus
                                }
                              </span>
                            </div>
                          </td>

                          <td className="px-5 py-4 align-top text-right">
                            <button
                              onClick={() =>
                                toggleDetails(
                                  vuln.id
                                )
                              }
                              className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white"
                            >
                              {expanded ? (
                                <>
                                  <EyeOff className="h-3.5 w-3.5" />
                                  Masquer
                                </>
                              ) : (
                                <>
                                  <Eye className="h-3.5 w-3.5" />
                                  Détails
                                </>
                              )}
                            </button>
                          </td>
                        </tr>
                      );
                    }
                  )}
                </tbody>
              </table>

              {/* DETAILS */}

              {filteredVulnerabilities.map(
                (vuln) => {
                  if (
                    expandedVulnerability !==
                    vuln.id
                  ) {
                    return null;
                  }

                  const isCreatingTicket =
                    creatingTicketId ===
                    vuln.id;

                  return (
                    <div
                      key={`${vuln.id}-details`}
                      className="border-t border-slate-800 bg-slate-950/60"
                    >
                      <div className="p-5 md:p-6">

                        {/* HEADER DETAILS */}

                        <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                          <div className="space-y-2">
                            <div className="flex flex-wrap items-center gap-3">
                              <SeverityBadge
                                severity={
                                  vuln.severity
                                }
                              />

                              <h3 className="text-lg font-semibold text-white">
                                {
                                  vuln.name
                                }
                              </h3>
                            </div>

                            <p className="text-xs text-slate-500">
                              Source : Greenbone / OpenVAS
                            </p>
                          </div>

                          <button
                            onClick={() =>
                              handleCreateGlpiTicket(
                                vuln
                              )
                            }
                            disabled={
                              isCreatingTicket ||
                              !canCreateTicket
                            }
                            title={
                              !canCreateTicket
                                ? "Permission TICKET_CREATE requise"
                                : undefined
                            }
                            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {isCreatingTicket ? (
                              <>
                                <RefreshCw className="h-4 w-4 animate-spin" />
                                Création...
                              </>
                            ) : (
                              <>
                                <Ticket className="h-4 w-4" />
                                Créer un ticket GLPI
                              </>
                            )}
                          </button>
                        </div>

                        {/* CONTENU */}

                        <div className="grid gap-5 lg:grid-cols-2">

                          {/* PREUVE */}

                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                              Preuve
                            </h4>

                            <div className="min-h-[140px] rounded-xl border border-slate-800/80 bg-slate-900/50 p-4 font-mono text-xs leading-relaxed text-slate-400 whitespace-pre-wrap">
                              {
                                vuln.proof ||
                                "Aucune preuve fournie par Greenbone."
                              }
                            </div>
                          </div>

                          {/* SOLUTION */}

                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                              Solution
                            </h4>

                            <div className="min-h-[140px] rounded-xl border border-slate-800/80 bg-slate-900/50 p-4 text-xs leading-relaxed text-slate-400 whitespace-pre-wrap">
                              {
                                vuln.solution ||
                                "Aucune solution fournie par Greenbone."
                              }
                            </div>
                          </div>

                          {/* DESCRIPTION */}

                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                              Description
                            </h4>

                            <div className="rounded-xl border border-slate-800/80 bg-slate-900/50 p-4 text-xs leading-relaxed text-slate-400 whitespace-pre-wrap">
                              {
                                vuln.description ||
                                "Aucune description disponible."
                              }
                            </div>
                          </div>

                          {/* INFOS TECHNIQUES */}

                          <div className="space-y-2">
                            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                              Informations techniques
                            </h4>

                            <div className="rounded-xl border border-slate-800/80 bg-slate-900/50 p-4">
                              <div className="grid grid-cols-2 gap-x-6 gap-y-4 text-xs">

                                <InfoItem
                                  label="Actif"
                                  value={
                                    vuln.asset
                                  }
                                />

                                <InfoItem
                                  label="Adresse IP"
                                  value={
                                    vuln.host
                                  }
                                />

                                <InfoItem
                                  label="Hostname"
                                  value={
                                    vuln.hostname
                                  }
                                />

                                <InfoItem
                                  label="Port"
                                  value={
                                    vuln.port !==
                                    "-"
                                      ? `${vuln.port}/${vuln.protocol}`
                                      : "—"
                                  }
                                />

                                <InfoItem
                                  label="CVSS"
                                  value={
                                    vuln.cvss ??
                                    "—"
                                  }
                                />

                                <InfoItem
                                  label="CVE"
                                  value={
                                    vuln.cve ||
                                    "—"
                                  }
                                />

                                <InfoItem
                                  label="Statut"
                                  value={
                                    vuln.vulnerabilityStatus
                                  }
                                />

                                <InfoItem
                                  label="Détection"
                                  value={formatDate(
                                    vuln.detectedAt
                                  )}
                                />

                              </div>
                            </div>
                          </div>
                        </div>

                        {/* NOTE GLPI */}

                        <div className="mt-5 flex items-start gap-3 rounded-xl border border-cyan-500/15 bg-cyan-500/5 px-4 py-3.5">
                          <Ticket className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />

                          <div>
                            <p className="text-sm font-medium text-cyan-300">
                              Remédiation GLPI
                            </p>

                            <p className="mt-1 text-xs leading-relaxed text-slate-500">
                              La solution Greenbone est utilisée pour préremplir le ticket GLPI avec l&apos;actif, la vulnérabilité, la preuve, la sévérité et les recommandations de remédiation.
                            </p>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          )}
        </section>

        {/* INFO GREENBONE */}

        <section className="rounded-2xl border border-slate-800/80 bg-slate-900/40 p-5 shadow-xl shadow-black/20">
          <div className="flex items-start gap-3.5">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan-500/10">
              <ShieldCheck className="h-4.5 w-4.5 text-cyan-400" />
            </div>

            <div>
              <h2 className="text-sm font-semibold text-slate-200">
                Résultats informatifs Greenbone
              </h2>

              <p className="mt-1.5 text-xs leading-relaxed text-slate-500">
                Les résultats Greenbone avec une sévérité de 0 sont des informations de découverte et d&apos;inventaire : systèmes, services, ports, versions, CPE, protocoles TLS, certificats, etc. Ils ne sont pas comptabilisés comme vulnérabilités dans cette vue.
              </p>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
}

/* =========================================================
   COMPONENTS
========================================================= */

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}) {
  const colorMap = {
    slate: {
      value: "text-white",
      iconBg: "bg-slate-500/10",
      icon: "text-slate-400",
      ring: "ring-slate-500/20",
    },

    red: {
      value: "text-red-400",
      iconBg: "bg-red-500/10",
      icon: "text-red-400",
      ring: "ring-red-500/20",
    },

    orange: {
      value: "text-orange-400",
      iconBg: "bg-orange-500/10",
      icon: "text-orange-400",
      ring: "ring-orange-500/20",
    },

    yellow: {
      value: "text-yellow-400",
      iconBg: "bg-yellow-500/10",
      icon: "text-yellow-400",
      ring: "ring-yellow-500/20",
    },

    blue: {
      value: "text-blue-400",
      iconBg: "bg-blue-500/10",
      icon: "text-blue-400",
      ring: "ring-blue-500/20",
    },
  };

  const styles =
    colorMap[color] ||
    colorMap.slate;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800/80 bg-slate-900/40 p-4 shadow-lg shadow-black/10">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-[11px] font-medium uppercase tracking-wider text-slate-500">
            {label}
          </p>

          <p
            className={`mt-2 text-2xl font-bold tabular-nums ${styles.value}`}
          >
            {value}
          </p>
        </div>

        <div
          className={`flex h-9 w-9 items-center justify-center rounded-xl ${styles.iconBg} ring-1 ${styles.ring}`}
        >
          <Icon
            className={`h-4 w-4 ${styles.icon}`}
          />
        </div>
      </div>
    </div>
  );
}

function InfoItem({
  label,
  value,
}) {
  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wider text-slate-600">
        {label}
      </p>

      <p className="mt-1 break-words font-medium text-slate-300">
        {value || "—"}
      </p>
    </div>
  );
}

function LoadingState({
  text,
}) {
  return (
    <div className="flex items-center justify-center gap-2.5 py-16 text-sm text-slate-500">
      <RefreshCw className="h-4 w-4 animate-spin text-cyan-500/70" />
      {text}
    </div>
  );
}

function EmptyState({
  icon: Icon,
  text,
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-800/50">
        <Icon className="h-6 w-6 text-slate-600" />
      </div>

      <p className="text-sm text-slate-500">
        {text}
      </p>
    </div>
  );
}

function extractProfile(
  description
) {
  if (!description) {
    return null;
  }

  const match = String(
    description
  ).match(
    /Scan Greenbone\s+([^.]+)/
  );

  return match
    ? match[1].trim()
    : null;
}

function formatDate(date) {
  if (!date) {
    return "—";
  }

  try {
    return new Date(
      date
    ).toLocaleString("fr-FR");
  } catch {
    return String(date);
  }
}

function StatusBadge({
  status,
}) {
  const normalized =
    String(
      status || ""
    ).toLowerCase();

  if (
    normalized.includes(
      "done"
    ) ||
    normalized.includes(
      "finished"
    ) ||
    normalized.includes(
      "completed"
    )
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2.5 py-1 text-xs font-medium text-emerald-400 ring-1 ring-emerald-500/20">
        <CheckCircle2 className="h-3.5 w-3.5" />
        Terminé
      </span>
    );
  }

  if (
    normalized.includes(
      "running"
    ) ||
    normalized.includes(
      "progress"
    )
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-cyan-500/10 px-2.5 py-1 text-xs font-medium text-cyan-400 ring-1 ring-cyan-500/20">
        <Clock className="h-3.5 w-3.5" />
        En cours
      </span>
    );
  }

  if (
    normalized.includes(
      "error"
    ) ||
    normalized.includes(
      "failed"
    )
  ) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400 ring-1 ring-red-500/20">
        <XCircle className="h-3.5 w-3.5" />
        Échec
      </span>
    );
  }

  return (
    <span className="rounded-full bg-slate-800 px-2.5 py-1 text-xs font-medium text-slate-400">
      {status || "Inconnu"}
    </span>
  );
}

function SeverityBadge({
  severity,
}) {
  const normalized =
    String(
      severity || ""
    )
      .trim()
      .toUpperCase();

  const styles = {
    CRITICAL:
      "bg-red-500/15 text-red-400 ring-red-500/30",

    HIGH:
      "bg-orange-500/15 text-orange-400 ring-orange-500/30",

    MEDIUM:
      "bg-yellow-500/15 text-yellow-400 ring-yellow-500/30",

    LOW:
      "bg-blue-500/15 text-blue-400 ring-blue-500/30",
  };

  const style =
    styles[normalized] ||
    "bg-slate-800 text-slate-400";

  return (
    <span
      className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-semibold tracking-wide ring-1 ${style}`}
    >
      {normalized ||
        "UNKNOWN"}
    </span>
  );
}