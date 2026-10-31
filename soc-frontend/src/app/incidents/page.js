"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import AuthGuard from "@/components/auth/AuthGuard";
import { useRBAC } from "@/components/auth/RBACContext";
import { getIncidents } from "@/lib/api";

import {
  LayoutDashboard,
  AlertTriangle,
  ShieldAlert,
  Fingerprint,
  ShieldCheck,
  Ticket,
  MonitorCheck,
  Settings,
} from "lucide-react";

function formatDate(value) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString("fr-FR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return value;
  }
}

function severityClass(severity) {
  switch (String(severity || "").toUpperCase()) {
    case "CRITICAL":
      return "border-red-500/30 bg-red-500/10 text-red-400";

    case "HIGH":
      return "border-orange-500/30 bg-orange-500/10 text-orange-400";

    case "MEDIUM":
      return "border-yellow-500/30 bg-yellow-500/10 text-yellow-400";

    case "LOW":
      return "border-cyan-500/30 bg-cyan-500/10 text-cyan-400";

    default:
      return "border-slate-700 bg-slate-800/50 text-slate-400";
  }
}

function severityDot(severity) {
  switch (String(severity || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-red-400 shadow-red-400/50";

    case "HIGH":
      return "bg-orange-400 shadow-orange-400/50";

    case "MEDIUM":
      return "bg-yellow-400 shadow-yellow-400/50";

    case "LOW":
      return "bg-cyan-400 shadow-cyan-400/50";

    default:
      return "bg-slate-500";
  }
}

function statusClass(status) {
  const value = String(status || "").toUpperCase();

  if (!value) {
    return "text-cyan-400";
  }

  if (
    value.includes("NEW") ||
    value.includes("NOUVEAU")
  ) {
    return "text-cyan-400";
  }

  if (
    value.includes("PROGRESS") ||
    value.includes("ANALYSE") ||
    value.includes("IN_PROGRESS")
  ) {
    return "text-orange-400";
  }

  if (
    value.includes("CLOSED") ||
    value.includes("CLOT") ||
    value.includes("RESOLVED")
  ) {
    return "text-emerald-400";
  }

  return "text-slate-400";
}

function statusDot(status) {
  const value = String(status || "").toUpperCase();

  if (
    value.includes("NEW") ||
    value.includes("NOUVEAU")
  ) {
    return "bg-cyan-400 shadow-cyan-400/40";
  }

  if (
    value.includes("PROGRESS") ||
    value.includes("ANALYSE") ||
    value.includes("IN_PROGRESS")
  ) {
    return "bg-orange-400 shadow-orange-400/40";
  }

  if (
    value.includes("CLOSED") ||
    value.includes("CLOT") ||
    value.includes("RESOLVED")
  ) {
    return "bg-emerald-400 shadow-emerald-400/40";
  }

  return "bg-slate-500";
}

export default function IncidentsPage() {
  const router = useRouter();

  const {
    user,
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadIncidents = hasPermission("INCIDENT_READ");
  const canReadAlerts = hasPermission("ALERT_READ");
  const canReadEvents = hasPermission("EVENT_READ");
  const canReadIOC = hasPermission("IOC_READ");
  const canReadAssets = hasPermission("ASSET_READ");
  const canReadTickets = hasPermission("TICKET_READ");
  const canManageRoles = hasPermission("ROLE_MANAGE");

  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;

    async function loadIncidents() {
      if (!canReadIncidents) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setError("");

        const data = await getIncidents();

        if (cancelled) return;

        setIncidents(
          Array.isArray(data)
            ? data
            : data?.items || []
        );
      } catch (err) {
        if (!cancelled) {
          setError(
            err?.message ||
              "Impossible de charger les incidents."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (!rbacLoading) {
      loadIncidents();
    }

    return () => {
      cancelled = true;
    };
  }, [rbacLoading, canReadIncidents]);

  const criticalCount = incidents.filter(
    (incident) =>
      String(incident.severite || "").toUpperCase() ===
      "CRITICAL"
  ).length;

  const highCount = incidents.filter(
    (incident) =>
      String(incident.severite || "").toUpperCase() ===
      "HIGH"
  ).length;

  const activeCount = incidents.filter((incident) => {
    const status = String(
      incident.statut || ""
    ).toUpperCase();

    return (
      status.includes("NEW") ||
      status.includes("NOUVEAU") ||
      status.includes("PROGRESS") ||
      status.includes("IN_PROGRESS")
    );
  }).length;

  const userDisplayName =
    [user?.prenom, user?.nom]
      .filter(Boolean)
      .join(" ")
      .trim() ||
    user?.nom_utilisateur ||
    "Utilisateur";

  const userRole =
    user?.roles?.[0] ||
    "Utilisateur";

  const userInitial = (
    user?.prenom?.[0] ||
    user?.nom?.[0] ||
    user?.nom_utilisateur?.[0] ||
    "U"
  ).toUpperCase();

  if (rbacLoading) {
    return (
      <AuthGuard>
        <div className="min-h-screen bg-[#070b14] text-slate-200">
          <div className="flex min-h-screen items-center justify-center">
            <div className="rounded-xl border border-slate-800 bg-[#0a0f1c] px-6 py-5 text-sm text-slate-500">
              Vérification des permissions...
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  if (!canReadIncidents) {
    return (
      <AuthGuard>
        <div className="min-h-screen bg-[#070b14] p-6 text-slate-200">
          <div className="mx-auto max-w-2xl pt-20">
            <div className="rounded-2xl border border-red-500/20 bg-red-950/20 p-6">
              <div className="flex items-center gap-3">
                <span className="text-lg text-red-400">
                  !
                </span>

                <div className="text-sm font-semibold text-red-400">
                  Accès refusé
                </div>
              </div>

              <p className="mt-3 text-sm text-slate-400">
                Votre compte ne possède pas la permission nécessaire
                pour consulter les incidents.
              </p>

              <button
                type="button"
                onClick={() => router.push("/dashboard")}
                className="mt-5 rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-300 transition hover:bg-slate-800/60 hover:text-white"
              >
                Retour au Dashboard
              </button>
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  return (
    <AuthGuard>
      <div className="min-h-screen bg-[#070b14] text-slate-200">
        <div className="flex min-h-screen">

          {/* SIDEBAR */}

          <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-slate-800/80 bg-[#0a0e17]/90 backdrop-blur-sm lg:flex">

            <div className="flex h-16 shrink-0 items-center gap-3 border-b border-slate-800/80 px-5">
              <div className="flex h-8 w-8 items-center justify-center rounded-md bg-cyan-500 text-sm font-bold text-slate-950">
                S
              </div>

              <div className="leading-tight">
                <div className="text-[13px] font-semibold text-white">
                  SOC Platform
                </div>

                <div className="text-[10px] text-slate-500">
                  Security Operations
                </div>
              </div>
            </div>

            <nav className="flex-1 overflow-y-auto px-3 py-4">

              <a
                href="/dashboard"
                className="mb-4 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
              >
                <LayoutDashboard
                  className="h-4 w-4"
                  strokeWidth={2}
                />
                Dashboard
              </a>

              {/* OPÉRATIONS */}

              <div className="mb-5">

                <div className="mb-1.5 flex items-center gap-2 px-3 text-[11px] font-medium text-slate-600">
                  <span className="h-3 w-[2px] rounded-full bg-slate-700" />
                  Opérations
                </div>

                {canReadAlerts && (
                  <a
                    href="/alerts"
                    className="mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                  >
                    <AlertTriangle
                      className="h-4 w-4"
                      strokeWidth={2}
                    />
                    Alertes
                  </a>
                )}

                {canReadIncidents && (
                  <a
                    href="/incidents"
                    className="mb-0.5 flex items-center gap-2.5 rounded-md bg-cyan-500/10 px-3 py-2 text-[13px] font-medium text-cyan-400 ring-1 ring-inset ring-cyan-500/20"
                  >
                    <ShieldAlert
                      className="h-4 w-4"
                      strokeWidth={2}
                    />
                    Incidents
                  </a>
                )}

                {canReadIOC && (
                  <a
                    href="/ioc"
                    className="mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                  >
                    <Fingerprint
                      className="h-4 w-4"
                      strokeWidth={2}
                    />
                    IOC
                  </a>
                )}

              </div>

              {/* SÉCURITÉ */}

              {(canReadAssets ||
                canReadTickets ||
                canReadEvents) && (
                <div className="mb-5">

                  <div className="mb-1.5 flex items-center gap-2 px-3 text-[11px] font-medium text-slate-600">
                    <span className="h-3 w-[2px] rounded-full bg-slate-700" />
                    Sécurité
                  </div>

                  {canReadAssets && (
                    <a
                      href="/vulnerabilities"
                      className="mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                    >
                      <ShieldCheck
                        className="h-4 w-4"
                        strokeWidth={2}
                      />
                      Vulnérabilités
                    </a>
                  )}

                  {canReadTickets && (
                    <a
                      href="/glpi"
                      className="mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                    >
                      <Ticket
                        className="h-4 w-4"
                        strokeWidth={2}
                      />
                      Tickets GLPI
                    </a>
                  )}

                  {canReadEvents && (
                    <a
                      href="/monitoring"
                      className="mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                    >
                      <MonitorCheck
                        className="h-4 w-4"
                        strokeWidth={2}
                      />
                      Monitoring
                    </a>
                  )}

                </div>
              )}

              {/* ADMINISTRATION */}

              {canManageRoles && (
                <a
                  href="/admin"
                  className="flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100"
                >
                  <Settings
                    className="h-4 w-4"
                    strokeWidth={2}
                  />
                  Administration
                </a>
              )}

            </nav>

            <div className="shrink-0 border-t border-slate-800/80 p-3">

              <div className="rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-3">

                <div className="mb-1.5 flex items-center gap-2">

                  <span className="relative flex h-1.5 w-1.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                    <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  </span>

                  <span className="text-xs font-medium text-slate-300">
                    SOC opérationnel
                  </span>

                </div>

                <p className="text-[11px] leading-relaxed text-slate-600">
                  Tous les services sont surveillés en continu.
                </p>

              </div>

            </div>

          </aside>

          {/* MAIN */}

          <main className="min-w-0 flex-1">

            {/* HEADER */}

            <header className="sticky top-0 z-20 flex h-20 items-center justify-between border-b border-slate-800/80 bg-[#090e19]/90 px-6 backdrop-blur-xl">

              <div>
                <h1 className="text-lg font-semibold text-white">
                  Gestion des incidents
                </h1>

                <p className="text-xs text-slate-500">
                  Centre de suivi et de traitement des incidents de sécurité
                </p>
              </div>

              <div className="flex items-center gap-4">

                <div className="hidden items-center text-[10px] text-slate-600 md:flex">
                  <span className="mr-2 h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
                  SOC opérationnel
                </div>

                <div className="flex h-9 w-9 items-center justify-center rounded-full border border-cyan-500/20 bg-cyan-500/10 text-sm font-semibold text-cyan-400 transition duration-200 hover:scale-105">
                  {userInitial}
                </div>

                <div className="hidden sm:block">
                  <p className="text-xs font-medium text-white">
                    {userDisplayName}
                  </p>

                  <p className="font-mono text-[10px] text-slate-600">
                    {userRole}
                  </p>
                </div>

              </div>

            </header>

            {/* CONTENT */}

            <div className="p-6">

              {/* PAGE TITLE */}

              <div className="mb-7 animate-[fadeIn_0.5s_ease-out]">

                <div className="flex flex-col justify-between gap-5 md:flex-row md:items-end">

                  <div>

                    <button
                      type="button"
                      onClick={() => router.push("/dashboard")}
                      className="mb-4 inline-flex items-center gap-2 text-xs text-slate-600 transition hover:text-cyan-400"
                    >
                      ← Retour au dashboard
                    </button>

                    <div className="mb-2 flex items-center gap-2">

                      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/50" />

                      <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-500">
                        Security Operations
                      </p>

                    </div>

                    <h2 className="text-2xl font-bold tracking-tight text-white">
                      Incidents
                    </h2>

                    <p className="mt-1 text-sm text-slate-500">
                      Incidents de sécurité nécessitant un suivi ou une réponse.
                    </p>

                  </div>

                  <div className="rounded-xl border border-slate-800 bg-[#0a0f1c] px-5 py-3 shadow-lg shadow-black/10 transition duration-300 hover:border-cyan-500/20">

                    <div className="flex items-center gap-3">

                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400">
                        <ShieldAlert
                          className="h-4 w-4"
                          strokeWidth={2}
                        />
                      </div>

                      <div>

                        <p className="text-[10px] uppercase tracking-wider text-slate-600">
                          Total incidents
                        </p>

                        <p className="text-lg font-bold text-white">
                          {loading
                            ? "..."
                            : incidents.length}
                        </p>

                      </div>

                    </div>

                  </div>

                </div>

              </div>

              {/* STATISTICS */}

              <div className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">

                {/* TOTAL */}

                <div className="rounded-lg border border-slate-800 bg-[#0a0f1c] px-4 py-3 transition-colors hover:border-slate-700">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                        Total incidents
                      </p>

                      <p className="mt-1 text-xl font-semibold text-white">
                        {loading
                          ? "..."
                          : incidents.length}
                      </p>

                    </div>

                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-slate-800/70 text-slate-400">

                      <ShieldAlert
                        className="h-4 w-4"
                        strokeWidth={2}
                      />

                    </div>

                  </div>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Incidents enregistrés
                  </p>

                </div>

                {/* CRITICAL */}

                <div className="rounded-lg border border-red-500/15 bg-[#0a0f1c] px-4 py-3 transition-colors hover:border-red-500/25">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                        Critical
                      </p>

                      <p className="mt-1 text-xl font-semibold text-red-400">
                        {loading
                          ? "..."
                          : criticalCount}
                      </p>

                    </div>

                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-red-500/10 text-red-400">

                      <AlertTriangle
                        className="h-4 w-4"
                        strokeWidth={2}
                      />

                    </div>

                  </div>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Incidents critiques
                  </p>

                </div>

                {/* HIGH */}

                <div className="rounded-lg border border-orange-500/15 bg-[#0a0f1c] px-4 py-3 transition-colors hover:border-orange-500/25">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                        High
                      </p>

                      <p className="mt-1 text-xl font-semibold text-orange-400">
                        {loading
                          ? "..."
                          : highCount}
                      </p>

                    </div>

                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-orange-500/10 text-orange-400">

                      <ShieldAlert
                        className="h-4 w-4"
                        strokeWidth={2}
                      />

                    </div>

                  </div>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Priorité élevée
                  </p>

                </div>

                {/* ACTIVE */}

                <div className="rounded-lg border border-cyan-500/15 bg-[#0a0f1c] px-4 py-3 transition-colors hover:border-cyan-500/25">

                  <div className="flex items-center justify-between">

                    <div>

                      <p className="text-[10px] font-medium uppercase tracking-wider text-slate-500">
                        Actifs
                      </p>

                      <p className="mt-1 text-xl font-semibold text-cyan-400">
                        {loading
                          ? "..."
                          : activeCount}
                      </p>

                    </div>

                    <div className="flex h-8 w-8 items-center justify-center rounded-md bg-cyan-500/10 text-cyan-400">

                      <MonitorCheck
                        className="h-4 w-4"
                        strokeWidth={2}
                      />

                    </div>

                  </div>

                  <p className="mt-1 text-[10px] text-slate-600">
                    Incidents à traiter
                  </p>

                </div>

              </div>

              {/* ERROR */}

              {error && (
                <div className="mb-6 animate-[fadeIn_0.3s_ease-out] rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-4">

                  <div className="flex gap-3">

                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-red-500/10 text-red-400">
                      !
                    </div>

                    <div>

                      <p className="text-sm font-medium text-red-400">
                        Erreur de connexion au backend
                      </p>

                      <p className="mt-1 text-xs text-red-400/70">
                        {error}
                      </p>

                    </div>

                  </div>

                </div>
              )}

              {/* TABLE */}

              <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#0a0f1c] shadow-xl shadow-black/10">

                <div className="flex flex-col justify-between gap-3 border-b border-slate-800 px-5 py-4 sm:flex-row sm:items-center">

                  <div>

                    <div className="flex items-center gap-2">

                      <h3 className="text-sm font-semibold text-white">
                        Liste des incidents
                      </h3>

                      {!loading && (
                        <span className="rounded-full border border-slate-800 bg-slate-950 px-2 py-0.5 text-[9px] font-medium text-slate-500">
                          {incidents.length}
                        </span>
                      )}

                    </div>

                    <p className="mt-1 text-xs text-slate-600">
                      Données récupérées directement depuis FastAPI.
                    </p>

                  </div>

                  <div className="flex items-center gap-2 text-[10px] text-slate-600">

                    <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/40" />

                    Surveillance active

                  </div>

                </div>

                <div className="overflow-x-auto">

                  <table className="w-full min-w-[950px] text-left">

                    <thead>

                      <tr className="border-b border-slate-800 bg-slate-950/30 text-[10px] uppercase tracking-wider text-slate-600">

                        <th className="px-5 py-3 font-medium">
                          ID
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Incident
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Sévérité
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Priorité
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Statut
                        </th>

                        <th className="px-5 py-3 font-medium">
                          TheHive
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Date
                        </th>

                      </tr>

                    </thead>

                    <tbody>

                      {loading && (
                        <tr>

                          <td
                            colSpan="7"
                            className="px-5 py-20 text-center"
                          >

                            <div className="mx-auto mb-4 h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />

                            <p className="text-sm text-slate-500">
                              Chargement des incidents...
                            </p>

                            <p className="mt-1 text-[10px] text-slate-700">
                              Connexion au backend SOC
                            </p>

                          </td>

                        </tr>
                      )}

                      {!loading &&
                        incidents.length === 0 && (
                          <tr>

                            <td
                              colSpan="7"
                              className="px-5 py-20 text-center"
                            >

                              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-slate-950 text-xl text-slate-700">
                                ●
                              </div>

                              <p className="mt-4 text-sm font-medium text-slate-400">
                                Aucun incident trouvé
                              </p>

                              <p className="mt-1 text-xs text-slate-600">
                                Aucun incident de sécurité n’est actuellement enregistré.
                              </p>

                            </td>

                          </tr>
                        )}

                      {!loading &&
                        incidents.map((incident, index) => {

                          const severity =
                            incident.severite ||
                            "UNKNOWN";

                          const status =
                            incident.statut ||
                            "NEW";

                          return (
                            <tr
                              key={incident.id_incident}
                              onClick={() =>
                                router.push(
                                  `/incidents/${incident.id_incident}`
                                )
                              }
                              className="group cursor-pointer border-b border-slate-800/60 transition-all duration-200 last:border-0 hover:bg-cyan-500/[0.035]"
                              style={{
                                animationDelay: `${Math.min(
                                  index * 35,
                                  350
                                )}ms`,
                              }}
                            >

                              {/* ID */}

                              <td className="px-5 py-4">

                                <span className="font-mono text-xs text-slate-600 transition-colors group-hover:text-cyan-500">
                                  #{incident.id_incident}
                                </span>

                              </td>

                              {/* INCIDENT */}

                              <td className="px-5 py-4">

                                <div className="max-w-[400px]">

                                  <div className="flex items-center gap-2">

                                    <span
                                      className={`h-1.5 w-1.5 shrink-0 rounded-full shadow-sm ${severityDot(
                                        severity
                                      )}`}
                                    />

                                    <p className="truncate text-xs font-medium text-slate-300 transition-colors group-hover:text-white">
                                      {incident.titre ||
                                        "Sans titre"}
                                    </p>

                                  </div>

                                  <p className="mt-1 truncate pl-3.5 text-[10px] text-slate-600">
                                    {incident.description ||
                                      "Aucune description"}
                                  </p>

                                </div>

                              </td>

                              {/* SEVERITY */}

                              <td className="px-5 py-4">

                                <span
                                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[9px] font-bold tracking-wide transition-transform duration-200 group-hover:scale-105 ${severityClass(
                                    severity
                                  )}`}
                                >

                                  <span
                                    className={`h-1 w-1 rounded-full ${severityDot(
                                      severity
                                    )}`}
                                  />

                                  {severity}

                                </span>

                              </td>

                              {/* PRIORITY */}

                              <td className="px-5 py-4">

                                <span className="text-xs font-medium text-slate-400">
                                  {incident.priorite ||
                                    "—"}
                                </span>

                              </td>

                              {/* STATUS */}

                              <td className="px-5 py-4">

                                <div className="flex items-center gap-2">

                                  <span
                                    className={`h-1.5 w-1.5 rounded-full shadow-sm ${statusDot(
                                      status
                                    )}`}
                                  />

                                  <span
                                    className={`text-xs font-medium ${statusClass(
                                      status
                                    )}`}
                                  >
                                    {status}
                                  </span>

                                </div>

                              </td>

                              {/* THEHIVE */}

                              <td className="px-5 py-4">

                                {incident.identifiant_thehive ? (
                                  <span className="inline-flex items-center rounded-md border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1 text-[9px] font-semibold text-emerald-400">
                                    Associé
                                  </span>
                                ) : (
                                  <span className="inline-flex items-center rounded-md border border-slate-800 bg-slate-950 px-2.5 py-1 text-[9px] font-medium text-slate-600">
                                    Non associé
                                  </span>
                                )}

                              </td>

                              {/* DATE */}

                              <td className="px-5 py-4">

                                <span className="whitespace-nowrap text-xs text-slate-600 transition-colors group-hover:text-slate-500">
                                  {formatDate(
                                    incident.date_creation
                                  )}
                                </span>

                              </td>

                            </tr>
                          );
                        })}

                    </tbody>

                  </table>

                </div>

              </div>

              {/* FOOTER */}

              {!loading &&
                incidents.length > 0 && (
                  <div className="mt-4 flex items-center justify-between px-1 text-[10px] text-slate-700">

                    <span>
                      Affichage de {incidents.length} incident
                      {incidents.length > 1 ? "s" : ""}
                    </span>

                    <span className="flex items-center gap-2">

                      <span className="h-1.5 w-1.5 rounded-full bg-emerald-400/70" />

                      Backend connecté

                    </span>

                  </div>
                )}

            </div>

          </main>

        </div>
      </div>
    </AuthGuard>
  );
}