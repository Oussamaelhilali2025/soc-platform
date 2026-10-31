"use client";

import { useEffect, useMemo, useState } from "react";
import AuthGuard from "@/components/auth/AuthGuard";
import { useRBAC } from "@/components/auth/RBACContext";
import { getAlerts } from "@/lib/api";
import {
  LayoutDashboard,
  AlertTriangle,
  ShieldAlert,
  Fingerprint,
  ShieldCheck,
  Ticket,
  MonitorCheck,
  Settings,
  Search,
  Bell,
} from "lucide-react";

const navSections = [
  {
    label: "Opérations",
    items: [
      {
        label: "Alertes",
        icon: AlertTriangle,
        href: "/alerts",
        permission: "ALERT_READ",
      },
      {
        label: "Incidents",
        icon: ShieldAlert,
        href: "/incidents",
        permission: "INCIDENT_READ",
      },
      {
        label: "IOC",
        icon: Fingerprint,
        href: "/ioc",
        permission: "IOC_READ",
      },
    ],
  },
  {
    label: "Sécurité",
    items: [
      {
        label: "Vulnérabilités",
        icon: ShieldCheck,
        href: "/vulnerabilities",
        permission: "ASSET_READ",
      },
      {
        label: "Tickets GLPI",
        icon: Ticket,
        href: "/glpi",
        permission: "TICKET_READ",
      },
      {
        label: "Monitoring",
        icon: MonitorCheck,
        href: "/monitoring",
        permission: "EVENT_READ",
      },
    ],
  },
];

function formatDate(value) {
  if (!value) {
    return "—";
  }

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

  if (value.includes("NEW") || value.includes("NOUVEAU")) {
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

  if (value.includes("NEW") || value.includes("NOUVEAU")) {
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

function sortAlertsByDateDesc(list) {
  return [...list].sort((a, b) => {
    const dateA = new Date(a.date_creation || 0).getTime();
    const dateB = new Date(b.date_creation || 0).getTime();

    return dateB - dateA;
  });
}

export default function AlertsPage() {
  const {
    user,
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadAlerts = hasPermission("ALERT_READ");
  const canReadIncidents = hasPermission("INCIDENT_READ");
  const canReadIOC = hasPermission("IOC_READ");
  const canReadAssets = hasPermission("ASSET_READ");
  const canReadTickets = hasPermission("TICKET_READ");
  const canReadEvents = hasPermission("EVENT_READ");
  const canManageRoles = hasPermission("ROLE_MANAGE");

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  useEffect(() => {
    async function loadAlerts() {
      if (!canReadAlerts) {
        setLoading(false);
        return;
      }

      try {
        setLoading(true);
        setError("");

        let data;

        try {
          // Variante 1 : getAlerts(page, pageSize)
          data = await getAlerts(1, 200);
        } catch {
          try {
            // Variante 2 : getAlerts({ page, page_size })
            data = await getAlerts({
              page: 1,
              page_size: 200,
            });
          } catch {
            // Variante 3 : sans paramètres
            data = await getAlerts();
          }
        }

        let list = [];

        if (Array.isArray(data)) {
          list = data;
        } else if (Array.isArray(data?.items)) {
          list = data.items;
        }

        setAlerts(sortAlertsByDateDesc(list));
      } catch (err) {
        console.error("Erreur récupération alertes :", err);

        setError(
          err.message || "Impossible de récupérer les alertes."
        );
      } finally {
        setLoading(false);
      }
    }

    if (!rbacLoading) {
      loadAlerts();
    }
  }, [rbacLoading, canReadAlerts]);

  const filteredAlerts = useMemo(() => {
    const searchValue = search.toLowerCase().trim();

    return alerts.filter((alert) => {
      const title = String(alert.titre || "").toLowerCase();
      const description = String(
        alert.description || ""
      ).toLowerCase();
      const source = String(
        alert.source_alerte || ""
      ).toLowerCase();
      const severity = String(
        alert.severite || ""
      ).toUpperCase();

      const matchesSearch =
        !searchValue ||
        title.includes(searchValue) ||
        description.includes(searchValue) ||
        source.includes(searchValue);

      const matchesSeverity =
        severityFilter === "ALL" ||
        severity === severityFilter;

      return matchesSearch && matchesSeverity;
    });
  }, [alerts, search, severityFilter]);

  const criticalCount = alerts.filter(
    (alert) =>
      String(alert.severite || "").toUpperCase() ===
      "CRITICAL"
  ).length;

  const highCount = alerts.filter(
    (alert) =>
      String(alert.severite || "").toUpperCase() ===
      "HIGH"
  ).length;

  const activeCount = alerts.filter((alert) => {
    const status = String(
      alert.statut || "NOUVEAU"
    ).toUpperCase();

    return (
      status.includes("NEW") ||
      status.includes("NOUVEAU") ||
      status.includes("PROGRESS") ||
      status.includes("ANALYSE") ||
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

  const userInitial =
    (
      user?.prenom?.[0] ||
      user?.nom?.[0] ||
      user?.nom_utilisateur?.[0] ||
      "U"
    ).toUpperCase();

  if (rbacLoading) {
    return (
      <AuthGuard>
        <div className="min-h-screen bg-[#080b12] text-slate-200">
          <div className="flex min-h-screen items-center justify-center">
            <div className="rounded-lg border border-slate-800 bg-[#0b0f19] px-6 py-5 text-sm text-slate-500">
              Vérification des permissions...
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  if (!canReadAlerts) {
    return (
      <AuthGuard>
        <div className="min-h-screen bg-[#080b12] p-6 text-slate-200">
          <div className="mx-auto max-w-2xl pt-20">
            <div className="rounded-2xl border border-red-500/20 bg-red-950/20 p-6">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-5 w-5 text-red-400" />

                <div className="text-sm font-semibold text-red-400">
                  Accès refusé
                </div>
              </div>

              <div className="mt-3 text-sm text-slate-400">
                Votre compte ne possède pas la permission nécessaire
                pour consulter les alertes.
              </div>

              <a
                href="/dashboard"
                className="mt-5 inline-flex rounded-lg border border-slate-700 px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-slate-800/60 hover:text-white"
              >
                Retour au Dashboard
              </a>
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  return (
    <AuthGuard>
      <div
        className="min-h-screen bg-[#080b12] text-slate-200"
        style={{
          backgroundImage:
            "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34,211,238,0.06), transparent), linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)",
          backgroundSize:
            "auto, 44px 44px, 44px 44px",
        }}
      >
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

              {navSections.map((section) => {
                const visibleItems = section.items.filter(
                  (item) => {
                    switch (item.permission) {
                      case "ALERT_READ":
                        return canReadAlerts;

                      case "INCIDENT_READ":
                        return canReadIncidents;

                      case "IOC_READ":
                        return canReadIOC;

                      case "ASSET_READ":
                        return canReadAssets;

                      case "TICKET_READ":
                        return canReadTickets;

                      case "EVENT_READ":
                        return canReadEvents;

                      default:
                        return false;
                    }
                  }
                );

                if (visibleItems.length === 0) {
                  return null;
                }

                return (
                  <div
                    key={section.label}
                    className="mb-5"
                  >
                    <div className="mb-1.5 flex items-center gap-2 px-3 text-[11px] font-medium text-slate-600">
                      <span className="h-3 w-[2px] rounded-full bg-slate-700" />
                      {section.label}
                    </div>

                    {visibleItems.map((item) => {
                      const isActive =
                        item.href === "/alerts";

                      return (
                        <a
                          key={item.label}
                          href={item.href}
                          className={`mb-0.5 flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition-colors ${
                            isActive
                              ? "bg-cyan-500/10 font-medium text-cyan-400 ring-1 ring-inset ring-cyan-500/20"
                              : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-100"
                          }`}
                        >
                          <item.icon
                            className="h-4 w-4"
                            strokeWidth={2}
                          />

                          {item.label}
                        </a>
                      );
                    })}
                  </div>
                );
              })}

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
            <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-800/80 bg-[#0a0e17]/80 px-6 backdrop-blur-md">
              <div>
                <h1 className="text-[15px] font-semibold text-white">
                  Alertes de sécurité
                </h1>

                <p className="text-[11px] text-slate-500">
                  Centre de surveillance et d'analyse des alertes
                </p>
              </div>

              <div className="flex items-center gap-3">
                <div className="hidden items-center gap-2 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-1.5 md:flex">
                  <Search
                    className="h-3.5 w-3.5 text-slate-600"
                    strokeWidth={2}
                  />

                  <input
                    type="text"
                    placeholder="Rechercher..."
                    value={search}
                    onChange={(event) =>
                      setSearch(event.target.value)
                    }
                    className="w-36 bg-transparent text-xs text-white outline-none placeholder:text-slate-600"
                  />

                  <span className="rounded border border-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-600">
                    ⌘K
                  </span>
                </div>

                <button
                  type="button"
                  className="relative flex h-8 w-8 items-center justify-center rounded-md border border-slate-800 bg-slate-950/60 text-slate-400 transition-colors hover:text-white"
                >
                  <Bell
                    className="h-4 w-4"
                    strokeWidth={2}
                  />

                  <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rose-500" />
                </button>

                <div className="hidden h-6 w-px bg-slate-800 sm:block" />

                <div className="flex items-center gap-2.5">
                  <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/15 text-xs font-semibold text-cyan-400">
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
              </div>
            </header>

            {/* CONTENT */}
            <div className="p-6">
              {/* PAGE TITLE */}
              <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end">
                <div>
                  <h2 className="text-xl font-semibold tracking-tight text-white">
                    Alertes
                  </h2>

                  <p className="mt-1 text-[13px] text-slate-500">
                    Alertes collectées et enregistrées par la plateforme SOC.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-950/40 px-3 py-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

                  <span className="text-[10px] text-slate-500">
                    Total alertes
                  </span>

                  <span className="h-3 w-px bg-slate-800" />

                  <span className="font-mono text-[10px] text-slate-400">
                    {loading ? "..." : alerts.length}
                  </span>
                </div>
              </div>

              {/* SUMMARY CARDS */}
              <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <span className="absolute inset-x-0 top-0 h-[2px] bg-slate-500" />

                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[13px] text-slate-500">
                        Total
                      </p>

                      <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white">
                        {loading ? "..." : alerts.length}
                      </p>

                      <p className="mt-2 text-[11px] text-slate-600">
                        Alertes enregistrées
                      </p>
                    </div>

                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-slate-500/10 ring-1 ring-inset ring-slate-500/20">
                      <AlertTriangle
                        className="h-4 w-4 text-slate-400"
                        strokeWidth={2}
                      />
                    </div>
                  </div>
                </div>

                <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <span className="absolute inset-x-0 top-0 h-[2px] bg-rose-500" />

                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[13px] text-slate-500">
                        Critical
                      </p>

                      <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-rose-400">
                        {loading ? "..." : criticalCount}
                      </p>

                      <p className="mt-2 text-[11px] text-slate-600">
                        Niveau critique
                      </p>
                    </div>

                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-rose-500/10 ring-1 ring-inset ring-rose-500/20">
                      <AlertTriangle
                        className="h-4 w-4 text-rose-400"
                        strokeWidth={2}
                      />
                    </div>
                  </div>
                </div>

                <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <span className="absolute inset-x-0 top-0 h-[2px] bg-amber-500" />

                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[13px] text-slate-500">
                        High
                      </p>

                      <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-amber-400">
                        {loading ? "..." : highCount}
                      </p>

                      <p className="mt-2 text-[11px] text-slate-600">
                        Niveau élevé
                      </p>
                    </div>

                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-amber-500/10 ring-1 ring-inset ring-amber-500/20">
                      <ShieldAlert
                        className="h-4 w-4 text-amber-400"
                        strokeWidth={2}
                      />
                    </div>
                  </div>
                </div>

                <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <span className="absolute inset-x-0 top-0 h-[2px] bg-cyan-500" />

                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-[13px] text-slate-500">
                        Actives
                      </p>

                      <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-cyan-400">
                        {loading ? "..." : activeCount}
                      </p>

                      <p className="mt-2 text-[11px] text-slate-600">
                        À traiter par le SOC
                      </p>
                    </div>

                    <div className="flex h-9 w-9 items-center justify-center rounded-md bg-cyan-500/10 ring-1 ring-inset ring-cyan-500/20">
                      <Bell
                        className="h-4 w-4 text-cyan-400"
                        strokeWidth={2}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* ERROR */}
              {error && (
                <div className="mb-6 flex items-center justify-between gap-4 rounded-lg border border-rose-500/20 bg-rose-500/5 px-4 py-3">
                  <div className="flex items-center gap-3">
                    <AlertTriangle
                      size={14}
                      className="shrink-0 text-rose-400"
                    />

                    <div>
                      <div className="text-xs font-medium text-rose-300">
                        Erreur de connexion au backend
                      </div>

                      <div className="mt-1 font-mono text-[10px] text-rose-400/60">
                        {error}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* FILTERS */}
              <div className="mb-4 rounded-lg border border-slate-800 bg-[#0b0f19] p-4">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                  <div className="flex min-w-0 flex-1 items-center gap-3">
                    <div className="flex min-w-0 flex-1 items-center gap-2 rounded-md border border-slate-800 bg-slate-950/60 px-3 py-2">
                      <Search
                        className="h-4 w-4 shrink-0 text-slate-600"
                        strokeWidth={2}
                      />

                      <input
                        type="text"
                        value={search}
                        onChange={(event) =>
                          setSearch(event.target.value)
                        }
                        placeholder="Rechercher une alerte, description ou source..."
                        className="min-w-0 flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600"
                      />

                      {search && (
                        <button
                          type="button"
                          onClick={() => setSearch("")}
                          className="text-[10px] text-slate-600 hover:text-slate-300"
                        >
                          Effacer
                        </button>
                      )}
                    </div>

                    <select
                      value={severityFilter}
                      onChange={(event) =>
                        setSeverityFilter(event.target.value)
                      }
                      className="rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400 outline-none focus:border-cyan-500/40"
                    >
                      <option value="ALL">
                        Toutes les sévérités
                      </option>

                      <option value="CRITICAL">
                        Critical
                      </option>

                      <option value="HIGH">
                        High
                      </option>

                      <option value="MEDIUM">
                        Medium
                      </option>

                      <option value="LOW">
                        Low
                      </option>
                    </select>
                  </div>

                  <div className="text-[10px] text-slate-600">
                    {filteredAlerts.length} résultat
                    {filteredAlerts.length !== 1
                      ? "s"
                      : ""}
                  </div>
                </div>
              </div>

              {/* TABLE */}
              <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19]">
                <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4">
                  <div>
                    <h3 className="text-[13px] font-semibold text-white">
                      Liste des alertes
                    </h3>

                    <p className="mt-1 text-[11px] text-slate-600">
                      Triées par date (plus récentes en premier)
                    </p>
                  </div>

                  <div className="flex items-center gap-2 text-[10px] text-slate-600">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
                    Surveillance active
                  </div>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full min-w-[950px] text-left">
                    <thead>
                      <tr className="border-b border-slate-800/80 text-[10px] text-slate-600">
                        <th className="px-5 py-3 font-medium">
                          ID
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Alerte
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Source
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Sévérité
                        </th>

                        <th className="px-5 py-3 font-medium">
                          Statut
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
                            colSpan={6}
                            className="px-5 py-14 text-center text-xs text-slate-600"
                          >
                            Chargement des alertes...
                          </td>
                        </tr>
                      )}

                      {!loading &&
                        filteredAlerts.length === 0 && (
                          <tr>
                            <td
                              colSpan={6}
                              className="px-5 py-14 text-center"
                            >
                              <AlertTriangle className="mx-auto mb-3 h-7 w-7 text-slate-700" />

                              <p className="text-xs text-slate-500">
                                Aucune alerte trouvée.
                              </p>

                              {(search ||
                                severityFilter !==
                                  "ALL") && (
                                <p className="mt-1 text-[10px] text-slate-700">
                                  Modifiez les critères de
                                  recherche.
                                </p>
                              )}
                            </td>
                          </tr>
                        )}

                      {!loading &&
                        filteredAlerts.map((alert) => {
                          const severity =
                            alert.severite ||
                            "UNKNOWN";

                          const status =
                            alert.statut ||
                            "NOUVEAU";

                          return (
                            <tr
                              key={alert.id_alerte}
                              onClick={() => {
                                window.location.href = `/alerts/${alert.id_alerte}`;
                              }}
                              className="cursor-pointer border-b border-slate-800/50 transition-colors last:border-0 hover:bg-slate-800/20"
                            >
                              <td className="px-5 py-4 font-mono text-xs text-slate-500">
                                {alert.identifiant_externe ||
                                  alert.id_alerte
                                    ?.slice?.(0, 8) ||
                                  alert.id_alerte}
                              </td>

                              <td className="px-5 py-4">
                                <div className="max-w-[420px]">
                                  <div className="flex items-center gap-2">
                                    <span
                                      className={`h-1.5 w-1.5 shrink-0 rounded-full ${severityDot(
                                        severity
                                      )}`}
                                    />

                                    <p className="truncate text-xs font-medium text-slate-300">
                                      {alert.titre ||
                                        "Alerte sans titre"}
                                    </p>
                                  </div>

                                  {alert.description && (
                                    <p className="mt-1 truncate pl-3.5 text-[10px] text-slate-600">
                                      {alert.description}
                                    </p>
                                  )}
                                </div>
                              </td>

                              <td className="px-5 py-4">
                                <span className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1 text-[10px] font-medium text-slate-400">
                                  {alert.source_alerte ||
                                    "—"}
                                </span>
                              </td>

                              <td className="px-5 py-4">
                                <span
                                  className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[9px] font-bold tracking-wide ${severityClass(
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

                              <td className="px-5 py-4">
                                <div className="flex items-center gap-2">
                                  <span
                                    className={`h-1.5 w-1.5 rounded-full ${statusDot(
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

                              <td className="px-5 py-4 font-mono text-xs text-slate-600">
                                {formatDate(
                                  alert.date_creation
                                )}
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
                filteredAlerts.length > 0 && (
                  <div className="mt-4 flex items-center justify-between px-1 text-[10px] text-slate-700">
                    <span>
                      Affichage de{" "}
                      {filteredAlerts.length} alerte
                      {filteredAlerts.length > 1
                        ? "s"
                        : ""}
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