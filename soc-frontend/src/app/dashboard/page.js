"use client";

import AuthGuard from "@/components/auth/AuthGuard";
import { useRBAC } from "@/components/auth/RBACContext";
import { useCallback, useEffect, useState } from "react";

import {
  getDashboardSummary,
  getAlerts,
  getAlertsOverTime,
  getAlertsBySeverity,
  getIncidentsByStatus,
  getIncidentsOverTime,
  getAlertsByCategory,
  getDashboardServices,
  getGlpiStats,
  logout,
} from "@/lib/api";

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
  ChevronRight,
  Activity,
  RefreshCw,
  ChevronLeft,
  LogOut,
} from "lucide-react";

const stats = [
  {
    label: "Événements",
    key: "evenement",
    description: "Événements enregistrés",
    icon: Activity,
    color: "cyan",
  },
  {
    label: "Alertes",
    key: "alerte",
    description: "Alertes de sécurité",
    icon: AlertTriangle,
    color: "red",
  },
  {
    label: "Incidents",
    key: "incident",
    description: "Incidents enregistrés",
    icon: ShieldAlert,
    color: "orange",
  },
  {
    label: "IOC détectés",
    key: "ioc",
    description: "Indicateurs de compromission",
    icon: Fingerprint,
    color: "violet",
  },
];

const secondaryStats = [
  { label: "Actifs", key: "actif" },
  { label: "Vulnérabilités", key: "vulnerabilite" },
  { label: "Scans vulnérabilité", key: "scan_vulnerabilite" },
  { label: "Tickets GLPI", key: "ticket_glpi" },
];

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

const severityStyles = {
  CRITICAL: {
    text: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/25",
    bar: "bg-rose-500",
    dot: "bg-rose-400",
  },
  HIGH: {
    text: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/25",
    bar: "bg-amber-500",
    dot: "bg-amber-400",
  },
  MEDIUM: {
    text: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/25",
    bar: "bg-yellow-500",
    dot: "bg-yellow-400",
  },
  LOW: {
    text: "text-sky-400",
    bg: "bg-sky-500/10",
    border: "border-sky-500/25",
    bar: "bg-sky-500",
    dot: "bg-sky-400",
  },
};

const statusStyles = {
  NEW: {
    text: "text-cyan-400",
    bar: "bg-cyan-500",
  },
  IN_PROGRESS: {
    text: "text-amber-400",
    bar: "bg-amber-500",
  },
  RESOLVED: {
    text: "text-emerald-400",
    bar: "bg-emerald-500",
  },
  CLOSED: {
    text: "text-slate-400",
    bar: "bg-slate-500",
  },
};

const statTokens = {
  cyan: {
    icon: "text-cyan-400",
    bg: "bg-cyan-500/10",
    ring: "ring-cyan-500/20",
    bar: "bg-cyan-400",
  },
  red: {
    icon: "text-rose-400",
    bg: "bg-rose-500/10",
    ring: "ring-rose-500/20",
    bar: "bg-rose-400",
  },
  orange: {
    icon: "text-amber-400",
    bg: "bg-amber-500/10",
    ring: "ring-amber-500/20",
    bar: "bg-amber-400",
  },
  violet: {
    icon: "text-violet-400",
    bg: "bg-violet-500/10",
    ring: "ring-violet-500/20",
    bar: "bg-violet-400",
  },
};

function severityClass(severity) {
  const s = severityStyles[severity];

  if (s) {
    return `${s.border} ${s.bg} ${s.text}`;
  }

  return "border-slate-600/30 bg-slate-500/10 text-slate-400";
}

function Bars({ data, color, unitLabel, loading }) {
  const maxValue = Math.max(
    ...data.map((point) => point.value),
    1
  );

  return (
    <div className="flex h-full w-full items-end gap-1.5">
      {data.map((item) => {
        const height =
          item.value === 0
            ? 0
            : Math.max((item.value / maxValue) * 100, 3);

        const showLabel =
          Number.parseInt(item.label, 10) % 2 === 0;

        return (
          <div
            key={item.label}
            className="flex h-full min-w-0 flex-1 flex-col justify-end"
          >
            <div
              className={`w-full rounded-t-[3px] ${color} transition-[height] duration-500 ease-out`}
              style={{
                height: `${height}%`,
                opacity: loading ? 0.3 : 1,
              }}
              title={`${item.label} : ${item.value} ${unitLabel}`}
            />

            <span
              className={`mt-2.5 block text-center font-mono text-[10px] ${
                showLabel ? "text-slate-600" : "text-transparent"
              }`}
            >
              {item.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

export default function DashboardPage() {
  const {
    user,
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const [summary, setSummary] = useState(null);

  const [glpiStats, setGlpiStats] = useState({
    total: 0,
    nouveaux: 0,
    en_traitement: 0,
    resolus: 0,
  });

  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [activity, setActivity] = useState([]);
  const [severityData, setSeverityData] = useState([]);
  const [incidentsStatusData, setIncidentsStatusData] = useState([]);
  const [incidentsActivity, setIncidentsActivity] = useState([]);

  const [alertPeriod, setAlertPeriod] = useState("24h");
  const [incidentPeriod, setIncidentPeriod] = useState("24h");

  const [categoryData, setCategoryData] = useState([]);
  const [servicesData, setServicesData] = useState([]);

  const [lastUpdated, setLastUpdated] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarReady, setSidebarReady] = useState(false);

  const [userMenuOpen, setUserMenuOpen] = useState(false);

  useEffect(() => {
    try {
      const saved = localStorage.getItem(
        "soc_sidebar_collapsed"
      );

      if (saved === "true") {
        setSidebarCollapsed(true);
      } else if (saved === "false") {
        setSidebarCollapsed(false);
      }
    } catch (err) {
      console.error(
        "Impossible de restaurer l'état du sidebar :",
        err
      );
    } finally {
      setSidebarReady(true);
    }
  }, []);

  useEffect(() => {
    if (!sidebarReady) {
      return;
    }

    try {
      localStorage.setItem(
        "soc_sidebar_collapsed",
        String(sidebarCollapsed)
      );
    } catch (err) {
      console.error(
        "Impossible de mémoriser l'état du sidebar :",
        err
      );
    }
  }, [sidebarCollapsed, sidebarReady]);

  const toggleSidebar = () => {
    setSidebarCollapsed((current) => !current);
  };

  /*
   * IMPORTANT :
   * On ne vérifie jamais les permissions tant que RBAC
   * n'a pas terminé de charger l'utilisateur.
   */
  const loadDashboard = useCallback(async () => {
    if (rbacLoading) {
      return;
    }

    if (!user) {
      return;
    }

    if (!hasPermission("ALERT_READ")) {
      setLoading(false);
      setRefreshing(false);
      setError(
        "Vous ne disposez pas de la permission nécessaire pour consulter le Dashboard."
      );
      return;
    }

    try {
      setRefreshing(true);
      setError("");

      const [
        summaryData,
        alertsData,
        severityDataResponse,
        incidentsStatusResponse,
        categoryDataResponse,
        servicesResponse,
        glpiStatsResponse,
      ] = await Promise.all([
        getDashboardSummary(),
        getAlerts(),
        getAlertsBySeverity(),
        getIncidentsByStatus(),
        getAlertsByCategory(),
        getDashboardServices(),
        getGlpiStats(),
      ]);

      setSummary(summaryData);

      setGlpiStats(
        glpiStatsResponse || {
          total: 0,
          nouveaux: 0,
          en_traitement: 0,
          resolus: 0,
        }
      );

      const alertsList = Array.isArray(alertsData)
        ? alertsData
        : Array.isArray(alertsData?.items)
        ? alertsData.items
        : [];

      setRecentAlerts(alertsList.slice(0, 10));

      setSeverityData(
        Array.isArray(severityDataResponse)
          ? severityDataResponse
          : []
      );

      setIncidentsStatusData(
        Array.isArray(incidentsStatusResponse)
          ? incidentsStatusResponse
          : []
      );

      setCategoryData(
        Array.isArray(categoryDataResponse)
          ? categoryDataResponse
          : []
      );

      setServicesData(
        Array.isArray(servicesResponse)
          ? servicesResponse
          : []
      );

      setLastUpdated(new Date());
    } catch (err) {
      console.error(
        "Erreur chargement Dashboard :",
        err
      );

      setError(
        err?.message ||
          "Impossible de charger les données du Dashboard."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [
    rbacLoading,
    user,
    hasPermission,
  ]);

  /*
   * CHARGEMENT PRINCIPAL
   *
   * On attend :
   * 1. que RBAC soit chargé
   * 2. qu'un utilisateur existe
   * 3. que sa permission soit connue
   */
  useEffect(() => {
    if (rbacLoading) {
      return;
    }

    if (!user) {
      return;
    }

    loadDashboard();

    const interval = setInterval(() => {
      if (
        document.visibilityState === "visible"
      ) {
        loadDashboard();
      }
    }, 30000);

    return () => {
      clearInterval(interval);
    };
  }, [
    rbacLoading,
    user,
    loadDashboard,
  ]);

  /*
   * ACTIVITÉ DES ALERTES
   */
  useEffect(() => {
    if (rbacLoading || !user) {
      return;
    }

    if (!hasPermission("ALERT_READ")) {
      return;
    }

    let isMounted = true;

    async function loadAlertActivity() {
      try {
        const data =
          await getAlertsOverTime(alertPeriod);

        if (isMounted) {
          setActivity(
            Array.isArray(data) ? data : []
          );
        }
      } catch (err) {
        console.error(
          "Erreur activité des alertes :",
          err
        );
      }
    }

    loadAlertActivity();

    const interval = setInterval(() => {
      loadAlertActivity();
    }, 30000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [
    alertPeriod,
    rbacLoading,
    user,
    hasPermission,
  ]);

  /*
   * ACTIVITÉ DES INCIDENTS
   */
  useEffect(() => {
    if (rbacLoading || !user) {
      return;
    }

    if (!hasPermission("ALERT_READ")) {
      return;
    }

    let isMounted = true;

    async function loadIncidentActivity() {
      try {
        const data =
          await getIncidentsOverTime(
            incidentPeriod
          );

        if (isMounted) {
          setIncidentsActivity(
            Array.isArray(data) ? data : []
          );
        }
      } catch (err) {
        console.error(
          "Erreur évolution des incidents :",
          err
        );
      }
    }

    loadIncidentActivity();

    const interval = setInterval(() => {
      loadIncidentActivity();
    }, 30000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [
    incidentPeriod,
    rbacLoading,
    user,
    hasPermission,
  ]);

  const roleLabel =
    user?.roles?.length > 0
      ? user.roles[0]
      : "UTILISATEUR";

  const displayName =
    user?.prenom || user?.nom
      ? `${user?.prenom || ""} ${
          user?.nom || ""
        }`.trim()
      : user?.nom_utilisateur || "Utilisateur";

  const initials =
    `${user?.prenom?.[0] || ""}${
      user?.nom?.[0] || ""
    }`.toUpperCase() ||
    user?.nom_utilisateur?.[0]?.toUpperCase() ||
    "U";

  return (
    <AuthGuard>
      {/*
       * IMPORTANT :
       * Tant que RBAC n'est pas terminé, aucune vérification
       * de permission n'est effectuée.
       */}
      {rbacLoading ? (
        <div className="flex min-h-screen items-center justify-center bg-[#080b12] text-slate-400">
          Chargement des permissions...
        </div>
      ) : !user ? (
        <div className="flex min-h-screen items-center justify-center bg-[#080b12] px-6 text-slate-200">
          <div className="w-full max-w-md rounded-lg border border-slate-800 bg-[#0b0f19] p-6 text-center">
            <div className="mx-auto mb-4 flex h-10 w-10 items-center justify-center rounded-full bg-rose-500/10 text-rose-400">
              <ShieldAlert
                className="h-5 w-5"
                strokeWidth={2}
              />
            </div>

            <h1 className="text-sm font-semibold text-white">
              Session utilisateur indisponible
            </h1>

            <p className="mt-2 text-xs leading-relaxed text-slate-500">
              Impossible de récupérer les informations
              de votre compte.
            </p>
          </div>
        </div>
      ) : !hasPermission("ALERT_READ") ? (
        <div className="flex min-h-screen items-center justify-center bg-[#080b12] px-6 text-slate-200">
          <div className="w-full max-w-md rounded-lg border border-slate-800 bg-[#0b0f19] p-6 text-center">
            <div className="mx-auto mb-4 flex h-10 w-10 items-center justify-center rounded-full bg-rose-500/10 text-rose-400">
              <ShieldAlert
                className="h-5 w-5"
                strokeWidth={2}
              />
            </div>

            <h1 className="text-sm font-semibold text-white">
              Accès refusé
            </h1>

            <p className="mt-2 text-xs leading-relaxed text-slate-500">
              Votre compte ne possède pas la permission
              nécessaire pour consulter le Dashboard.
            </p>
          </div>
        </div>
      ) : (
        <div
          className="min-h-screen bg-[#080b12] text-slate-200"
          style={{
            backgroundImage:
              "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34,211,238,0.06), transparent), linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)",
            backgroundSize:
              "auto, 44px 44px, 44px 44px",
          }}
        >
          <div className="min-h-screen">
            <aside
              className={`fixed inset-y-0 left-0 z-40 hidden shrink-0 border-r border-slate-800/80 bg-[#0a0e17]/95 backdrop-blur-sm transition-[width] duration-200 lg:flex lg:flex-col ${
                sidebarCollapsed
                  ? "w-20"
                  : "w-64"
              }`}
            >
              <div
                className={`flex h-16 shrink-0 items-center border-b border-slate-800/80 ${
                  sidebarCollapsed
                    ? "justify-center px-3"
                    : "gap-3 px-5"
                }`}
              >
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-cyan-500 text-sm font-bold text-slate-950">
                  S
                </div>

                {!sidebarCollapsed && (
                  <div className="min-w-0 leading-tight">
                    <div className="text-[13px] font-semibold text-white">
                      SOC Platform
                    </div>

                    <div className="text-[10px] text-slate-500">
                      Security Operations
                    </div>
                  </div>
                )}
              </div>

              <nav
                className={`flex-1 overflow-y-auto py-4 ${
                  sidebarCollapsed
                    ? "px-2"
                    : "px-3"
                }`}
              >
                <a
                  href="/dashboard"
                  title={
                    sidebarCollapsed
                      ? "Dashboard"
                      : undefined
                  }
                  className={`mb-4 flex items-center rounded-md bg-cyan-500/10 py-2 text-[13px] font-medium text-cyan-400 ring-1 ring-inset ring-cyan-500/20 ${
                    sidebarCollapsed
                      ? "justify-center px-2"
                      : "gap-2.5 px-3"
                  }`}
                >
                  <LayoutDashboard
                    className="h-4 w-4 shrink-0"
                    strokeWidth={2}
                  />

                  {!sidebarCollapsed && (
                    <span>Dashboard</span>
                  )}
                </a>

                {navSections.map((section) => {
                  const visibleItems =
                    section.items.filter(
                      (item) =>
                        !item.permission ||
                        hasPermission(
                          item.permission
                        )
                    );

                  if (
                    visibleItems.length === 0
                  ) {
                    return null;
                  }

                  return (
                    <div
                      key={section.label}
                      className="mb-5"
                    >
                      {!sidebarCollapsed && (
                        <div className="mb-1.5 flex items-center gap-2 px-3 text-[11px] font-medium text-slate-600">
                          <span className="h-3 w-[2px] rounded-full bg-slate-700" />
                          {section.label}
                        </div>
                      )}

                      {visibleItems.map(
                        (item) => (
                          <a
                            key={item.label}
                            href={item.href}
                            title={
                              sidebarCollapsed
                                ? item.label
                                : undefined
                            }
                            className={`mb-0.5 flex items-center rounded-md py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100 ${
                              sidebarCollapsed
                                ? "justify-center px-2"
                                : "gap-2.5 px-3"
                            }`}
                          >
                            <item.icon
                              className="h-4 w-4 shrink-0"
                              strokeWidth={2}
                            />

                            {!sidebarCollapsed && (
                              <span>
                                {item.label}
                              </span>
                            )}
                          </a>
                        )
                      )}
                    </div>
                  );
                })}

                {hasPermission(
                  "ROLE_MANAGE"
                ) && (
                  <a
                    href="/admin"
                    title={
                      sidebarCollapsed
                        ? "Administration"
                        : undefined
                    }
                    className={`flex items-center rounded-md py-2 text-[13px] text-slate-400 transition-colors hover:bg-slate-800/50 hover:text-slate-100 ${
                      sidebarCollapsed
                        ? "justify-center px-2"
                        : "gap-2.5 px-3"
                    }`}
                  >
                    <Settings
                      className="h-4 w-4 shrink-0"
                      strokeWidth={2}
                    />

                    {!sidebarCollapsed && (
                      <span>
                        Administration
                      </span>
                    )}
                  </a>
                )}
              </nav>

              {!sidebarCollapsed && (
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
                      Tous les services sont
                      surveillés en continu.
                    </p>
                  </div>
                </div>
              )}

              <button
                type="button"
                onClick={toggleSidebar}
                title={
                  sidebarCollapsed
                    ? "Ouvrir le sidebar"
                    : "Réduire le sidebar"
                }
                className="absolute -right-3 top-[4.5rem] z-50 flex h-6 w-6 items-center justify-center rounded-full border border-slate-700 bg-[#0b0f19] text-slate-400 shadow-lg transition-colors hover:border-cyan-500/40 hover:text-cyan-400"
              >
                {sidebarCollapsed ? (
                  <ChevronRight
                    className="h-3.5 w-3.5"
                    strokeWidth={2}
                  />
                ) : (
                  <ChevronLeft
                    className="h-3.5 w-3.5"
                    strokeWidth={2}
                  />
                )}
              </button>
            </aside>

            <main
              className={`min-w-0 transition-[margin] duration-200 ${
                sidebarCollapsed
                  ? "lg:ml-20"
                  : "lg:ml-64"
              }`}
            >
              <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-800/80 bg-[#0a0e17]/80 px-6 backdrop-blur-md">
                <div>
                  <h1 className="text-[15px] font-semibold text-white">
                    Security Dashboard
                  </h1>

                  <p className="text-[11px] text-slate-500">
                    Vue globale de votre
                    environnement SOC
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

                  <div className="relative">
                    <button
                      type="button"
                      onClick={() =>
                        setUserMenuOpen(
                          (current) => !current
                        )
                      }
                      className="flex items-center gap-2.5 rounded-md px-2 py-1.5 transition-colors hover:bg-slate-800/50"
                    >
                      <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/15 text-xs font-semibold text-cyan-400">
                        {initials}
                      </div>

                      <div className="hidden text-left sm:block">
                        <p className="text-xs font-medium text-white">
                          {displayName}
                        </p>

                        <p className="font-mono text-[10px] text-slate-600">
                          {roleLabel}
                        </p>
                      </div>

                      <ChevronRight
                        className={`hidden h-3.5 w-3.5 text-slate-600 transition-transform sm:block ${
                          userMenuOpen
                            ? "rotate-90"
                            : ""
                        }`}
                        strokeWidth={2}
                      />
                    </button>

                    {userMenuOpen && (
                      <div className="absolute right-0 top-full z-50 mt-2 w-52 overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] shadow-xl shadow-black/30">
                        <div className="border-b border-slate-800 px-4 py-3">
                          <p className="truncate text-xs font-medium text-white">
                            {displayName}
                          </p>

                          <p className="mt-1 truncate text-[10px] text-slate-600">
                            {user?.email ||
                              user?.nom_utilisateur ||
                              ""}
                          </p>

                          <p className="mt-1 font-mono text-[9px] text-cyan-400/70">
                            {roleLabel}
                          </p>
                        </div>

                        <button
                          type="button"
                          onClick={() => {
                            setUserMenuOpen(false);
                            logout();
                          }}
                          className="flex w-full items-center gap-2.5 px-4 py-3 text-left text-xs text-slate-400 transition-colors hover:bg-rose-500/10 hover:text-rose-400"
                        >
                          <LogOut
                            className="h-4 w-4"
                            strokeWidth={2}
                          />

                          <span>
                            Déconnexion
                          </span>
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </header>

              <div className="p-6">
                <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end">
                  <div>
                    <h2 className="text-xl font-semibold tracking-tight text-white">
                      Centre des opérations
                    </h2>

                    <p className="mt-1 text-[13px] text-slate-500">
                      Surveillance en temps réel de votre
                      infrastructure de sécurité.
                    </p>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-950/40 px-3 py-1.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

                    <span className="text-[10px] text-slate-500">
                      Auto · 30 s
                    </span>

                    <span className="h-3 w-px bg-slate-800" />

                    <span className="text-[10px] text-slate-500">
                      Maj{" "}
                      <span className="font-mono text-slate-400">
                        {lastUpdated
                          ? new Intl.DateTimeFormat(
                              "fr-FR",
                              {
                                hour: "2-digit",
                                minute: "2-digit",
                                second: "2-digit",
                              }
                            ).format(
                              lastUpdated
                            )
                          : "—"}
                      </span>
                    </span>

                    <span className="h-3 w-px bg-slate-800" />

                    <button
                      type="button"
                      onClick={loadDashboard}
                      disabled={refreshing}
                      className="flex items-center gap-1.5 text-[10px] font-medium text-slate-400 transition-colors hover:text-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <RefreshCw
                        size={11}
                        className={
                          refreshing
                            ? "animate-spin"
                            : ""
                        }
                      />

                      {refreshing
                        ? "Actualisation..."
                        : "Actualiser"}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="mb-6 flex items-center justify-between gap-4 rounded-lg border border-rose-500/20 bg-rose-500/5 px-4 py-3">
                    <div className="flex items-center gap-3">
                      <AlertTriangle
                        size={14}
                        className="shrink-0 text-rose-400"
                      />

                      <div>
                        <div className="text-xs font-medium text-rose-300">
                          Erreur de connexion au
                          backend
                        </div>

                        <div className="mt-1 font-mono text-[10px] text-rose-400/60">
                          {error}
                        </div>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={loadDashboard}
                      disabled={refreshing}
                      className="shrink-0 text-[10px] font-medium text-rose-400 transition-colors hover:text-rose-300 disabled:opacity-50"
                    >
                      Réessayer
                    </button>
                  </div>
                )}

                <div className="mb-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  {stats.map((stat) => {
                    const tokens =
                      statTokens[stat.color];
                    const Icon = stat.icon;

                    return (
                      <div
                        key={stat.label}
                        className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5 transition-colors hover:border-slate-700"
                      >
                        <span
                          className={`absolute inset-x-0 top-0 h-[2px] ${tokens.bar}`}
                        />

                        <div className="flex items-start justify-between">
                          <div>
                            <p className="text-[13px] text-slate-500">
                              {stat.label}
                            </p>

                            <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white tabular-nums">
                              {loading ? (
                                <span className="inline-block h-6 w-14 animate-pulse rounded bg-slate-800" />
                              ) : (
                                (
                                  summary?.[
                                    stat.key
                                  ] ?? 0
                                ).toLocaleString(
                                  "fr-FR"
                                )
                              )}
                            </p>

                            <p className="mt-2 text-[11px] text-slate-600">
                              {stat.description}
                            </p>
                          </div>

                          <div
                            className={`flex h-9 w-9 items-center justify-center rounded-md ${tokens.bg} ring-1 ring-inset ${tokens.ring}`}
                          >
                            <Icon
                              className={`h-4 w-4 ${tokens.icon}`}
                              strokeWidth={2}
                            />
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  {secondaryStats.map((item) => (
                    <div
                      key={item.key}
                      className="rounded-lg border border-slate-800/70 bg-[#0b0f19]/60 px-4 py-3"
                    >
                      <p className="text-[11px] text-slate-600">
                        {item.label}
                      </p>

                      <p className="mt-1 font-mono text-lg font-semibold text-white tabular-nums">
                        {loading ? (
                          <span className="inline-block h-5 w-10 animate-pulse rounded bg-slate-800" />
                        ) : (
                          (
                            summary?.[item.key] ??
                            0
                          ).toLocaleString(
                            "fr-FR"
                          )
                        )}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="mb-6 rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <div className="mb-5 flex items-center justify-between">
                    <div>
                      <h3 className="text-[13px] font-semibold text-white">
                        Support GLPI
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        État actuel des tickets du
                        système ITSM
                      </p>
                    </div>

                    {hasPermission(
                      "TICKET_READ"
                    ) && (
                      <a
                        href="/glpi"
                        className="flex items-center gap-1 text-[11px] font-medium text-cyan-400 transition-colors hover:text-cyan-300"
                      >
                        Voir les tickets
                        <ChevronRight
                          className="h-3.5 w-3.5"
                          strokeWidth={2}
                        />
                      </a>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                    <div className="rounded-md border border-slate-800/70 bg-slate-950/40 px-4 py-3">
                      <p className="text-[11px] text-slate-600">
                        Total
                      </p>

                      <p className="mt-1 font-mono text-xl font-semibold text-white tabular-nums">
                        {loading
                          ? "—"
                          : glpiStats.total}
                      </p>
                    </div>

                    <div className="rounded-md border border-slate-800/70 bg-slate-950/40 px-4 py-3">
                      <p className="text-[11px] text-slate-600">
                        Nouveaux
                      </p>

                      <p className="mt-1 font-mono text-xl font-semibold text-cyan-400 tabular-nums">
                        {loading
                          ? "—"
                          : glpiStats.nouveaux}
                      </p>
                    </div>

                    <div className="rounded-md border border-slate-800/70 bg-slate-950/40 px-4 py-3">
                      <p className="text-[11px] text-slate-600">
                        En traitement
                      </p>

                      <p className="mt-1 font-mono text-xl font-semibold text-amber-400 tabular-nums">
                        {loading
                          ? "—"
                          : glpiStats.en_traitement}
                      </p>
                    </div>

                    <div className="rounded-md border border-slate-800/70 bg-slate-950/40 px-4 py-3">
                      <p className="text-[11px] text-slate-600">
                        Résolus / clos
                      </p>

                      <p className="mt-1 font-mono text-xl font-semibold text-emerald-400 tabular-nums">
                        {loading
                          ? "—"
                          : glpiStats.resolus}
                      </p>
                    </div>
                  </div>
                </div>

                <div className="mb-6 grid gap-4 xl:grid-cols-3">
                  <div className="rounded-lg border border-slate-800 bg-[#0b0f19] p-5 xl:col-span-2">
                    <div className="mb-6 flex items-center justify-between">
                      <div>
                        <h3 className="text-[13px] font-semibold text-white">
                          Activité des alertes
                        </h3>

                        <p className="mt-1 text-[11px] text-slate-600">
                          {alertPeriod === "24h"
                            ? "Volume d'alertes sur les dernières 24 heures"
                            : alertPeriod === "7d"
                            ? "Volume d'alertes sur les 7 derniers jours"
                            : "Volume d'alertes sur les 30 derniers jours"}
                        </p>
                      </div>

                      <select
                        value={alertPeriod}
                        onChange={(e) =>
                          setAlertPeriod(
                            e.target.value
                          )
                        }
                        className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5 text-[11px] text-slate-400 outline-none"
                      >
                        <option value="24h">
                          24 heures
                        </option>
                        <option value="7d">
                          7 jours
                        </option>
                        <option value="30d">
                          30 jours
                        </option>
                      </select>
                    </div>

                    <div className="h-56 w-full">
                      <Bars
                        data={activity}
                        color="bg-cyan-500/70"
                        unitLabel="alertes"
                        loading={loading}
                      />
                    </div>

                    <div className="mt-4 flex items-center justify-between border-t border-slate-800/70 pt-3 text-[11px] text-slate-600">
                      <span>
                        Total alertes :{" "}
                        <span className="font-mono text-slate-400">
                          {loading
                            ? "—"
                            : activity.reduce(
                                (
                                  total,
                                  item
                                ) =>
                                  total +
                                  item.value,
                                0
                              )}
                        </span>
                      </span>

                      <span className="flex items-center gap-1.5">
                        <span className="h-2 w-2 rounded-full bg-cyan-400" />
                        Alertes détectées
                      </span>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                    <div className="mb-5">
                      <h3 className="text-[13px] font-semibold text-white">
                        Alertes par sévérité
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        Répartition des alertes de
                        sécurité
                      </p>
                    </div>

                    <div className="space-y-4">
                      {severityData.map(
                        (item) => {
                          const maxValue =
                            Math.max(
                              ...severityData.map(
                                (p) => p.value
                              ),
                              1
                            );

                          const percentage =
                            (item.value /
                              maxValue) *
                            100;

                          const s =
                            severityStyles[
                              item.label
                            ] ||
                            severityStyles.MEDIUM;

                          return (
                            <div
                              key={item.label}
                            >
                              <div className="mb-1.5 flex items-center justify-between">
                                <span
                                  className={`flex items-center gap-1.5 text-[11px] font-medium ${s.text}`}
                                >
                                  <span
                                    className={`h-1.5 w-1.5 rounded-full ${s.dot}`}
                                  />

                                  {item.label}
                                </span>

                                <span className="font-mono text-xs text-slate-500">
                                  {item.value}
                                </span>
                              </div>

                              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80">
                                <div
                                  className={`h-full rounded-full ${s.bar} transition-all duration-700`}
                                  style={{
                                    width: `${percentage}%`,
                                  }}
                                />
                              </div>
                            </div>
                          );
                        }
                      )}
                    </div>

                    <div className="mt-5 flex items-center justify-between border-t border-slate-800/70 pt-4">
                      <span className="text-[11px] text-slate-600">
                        Total alertes
                      </span>

                      <span className="font-mono text-sm font-semibold text-white">
                        {severityData.reduce(
                          (total, item) =>
                            total +
                            item.value,
                          0
                        )}
                      </span>
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                    <div className="mb-5">
                      <h3 className="text-[13px] font-semibold text-white">
                        Incidents par statut
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        Répartition des incidents du
                        SOC
                      </p>
                    </div>

                    <div className="space-y-4">
                      {incidentsStatusData.map(
                        (item) => {
                          const maxValue =
                            Math.max(
                              ...incidentsStatusData.map(
                                (p) => p.value
                              ),
                              1
                            );

                          const percentage =
                            (item.value /
                              maxValue) *
                            100;

                          const s =
                            statusStyles[
                              item.label
                            ] || {
                              text: "text-slate-400",
                              bar: "bg-slate-500",
                            };

                          return (
                            <div
                              key={item.label}
                            >
                              <div className="mb-1.5 flex items-center justify-between">
                                <span
                                  className={`text-[11px] font-medium ${s.text}`}
                                >
                                  {item.label}
                                </span>

                                <span className="font-mono text-xs text-slate-500">
                                  {item.value}
                                </span>
                              </div>

                              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80">
                                <div
                                  className={`h-full rounded-full ${s.bar} transition-all duration-700`}
                                  style={{
                                    width: `${percentage}%`,
                                  }}
                                />
                              </div>
                            </div>
                          );
                        }
                      )}
                    </div>

                    <div className="mt-5 flex items-center justify-between border-t border-slate-800/70 pt-4">
                      <span className="text-[11px] text-slate-600">
                        Total incidents
                      </span>

                      <span className="font-mono text-sm font-semibold text-white">
                        {incidentsStatusData.reduce(
                          (total, item) =>
                            total +
                            item.value,
                          0
                        )}
                      </span>
                    </div>
                  </div>

                  <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                    <span className="absolute inset-x-0 top-0 h-[2px] bg-slate-600" />

                    <div className="mb-5">
                      <h3 className="text-[13px] font-semibold text-white">
                        État des services
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        Infrastructure SOC
                      </p>
                    </div>

                    <div className="space-y-2">
                      {servicesData.map(
                        (service) => {
                          const isUp =
                            service.status ===
                            "UP";

                          const isUnknown =
                            service.status ===
                            "UNKNOWN";

                          return (
                            <div
                              key={service.name}
                              className="flex items-center justify-between border-b border-slate-800/50 py-3 last:border-0"
                            >
                              <div className="flex items-center gap-3">
                                <span
                                  className={`h-2 w-2 rounded-full ${
                                    isUp
                                      ? "bg-emerald-400"
                                      : isUnknown
                                      ? "bg-slate-500"
                                      : "bg-rose-400"
                                  }`}
                                />

                                <span className="text-xs text-slate-300">
                                  {
                                    service.name
                                  }
                                </span>
                              </div>

                              <div className="flex items-center gap-4">
                                <span
                                  className={`text-[10px] font-medium ${
                                    isUp
                                      ? "text-emerald-400"
                                      : isUnknown
                                      ? "text-slate-500"
                                      : "text-rose-400"
                                  }`}
                                >
                                  {isUp
                                    ? "Opérationnel"
                                    : isUnknown
                                    ? "Non configuré"
                                    : "Indisponible"}
                                </span>

                                <span className="w-14 text-right font-mono text-[10px] text-slate-600">
                                  {service.latency !==
                                  null
                                    ? `${service.latency} ms`
                                    : "—"}
                                </span>
                              </div>
                            </div>
                          );
                        }
                      )}
                    </div>
                  </div>
                </div>

                <div className="mb-6 rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <div className="mb-6 flex items-center justify-between">
                    <div>
                      <h3 className="text-[13px] font-semibold text-white">
                        Évolution des incidents
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        {incidentPeriod ===
                        "24h"
                          ? "Nombre d'incidents créés sur les dernières 24 heures"
                          : incidentPeriod ===
                            "7d"
                          ? "Nombre d'incidents créés sur les 7 derniers jours"
                          : "Nombre d'incidents créés sur les 30 derniers jours"}
                      </p>
                    </div>

                    <select
                      value={incidentPeriod}
                      onChange={(e) =>
                        setIncidentPeriod(
                          e.target.value
                        )
                      }
                      className="rounded-md border border-slate-800 bg-slate-950 px-2 py-1.5 text-[11px] text-slate-400 outline-none"
                    >
                      <option value="24h">
                        24 heures
                      </option>
                      <option value="7d">
                        7 jours
                      </option>
                      <option value="30d">
                        30 jours
                      </option>
                    </select>
                  </div>

                  <div className="h-56 w-full">
                    <Bars
                      data={incidentsActivity}
                      color="bg-amber-500/70"
                      unitLabel="incidents"
                      loading={loading}
                    />
                  </div>

                  <div className="mt-4 flex items-center justify-between border-t border-slate-800/70 pt-3 text-[11px] text-slate-600">
                    <span>
                      Total incidents :{" "}
                      <span className="font-mono text-slate-400">
                        {loading
                          ? "—"
                          : incidentsActivity.reduce(
                              (
                                total,
                                item
                              ) =>
                                total +
                                item.value,
                              0
                            )}
                      </span>
                    </span>

                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-amber-400" />
                      Incidents créés
                    </span>
                  </div>
                </div>

                <div className="mb-6 rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                  <div className="mb-5">
                    <h3 className="text-[13px] font-semibold text-white">
                      Types de détection
                    </h3>

                    <p className="mt-1 text-[11px] text-slate-600">
                      Répartition des alertes selon
                      la catégorie de détection
                    </p>
                  </div>

                  {categoryData.length ===
                  0 ? (
                    <div className="flex h-40 items-center justify-center text-xs text-slate-600">
                      Aucune catégorie de
                      détection disponible.
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {categoryData.map(
                        (item) => {
                          const maxValue =
                            Math.max(
                              ...categoryData.map(
                                (p) => p.value
                              ),
                              1
                            );

                          const percentage =
                            (item.value /
                              maxValue) *
                            100;

                          return (
                            <div
                              key={item.label}
                            >
                              <div className="mb-1.5 flex items-center justify-between">
                                <span className="text-[11px] font-medium text-violet-400">
                                  {item.label}
                                </span>

                                <span className="font-mono text-xs text-slate-500">
                                  {item.value}
                                </span>
                              </div>

                              <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800/80">
                                <div
                                  className="h-full rounded-full bg-violet-500 transition-all duration-700"
                                  style={{
                                    width: `${percentage}%`,
                                  }}
                                />
                              </div>
                            </div>
                          );
                        }
                      )}
                    </div>
                  )}

                  <div className="mt-5 flex items-center justify-between border-t border-slate-800/70 pt-4">
                    <span className="text-[11px] text-slate-600">
                      Total alertes catégorisées
                    </span>

                    <span className="font-mono text-sm font-semibold text-white">
                      {categoryData.reduce(
                        (total, item) =>
                          total + item.value,
                        0
                      )}
                    </span>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-[#0b0f19]">
                  <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4">
                    <div>
                      <h3 className="text-[13px] font-semibold text-white">
                        Alertes récentes
                      </h3>

                      <p className="mt-1 text-[11px] text-slate-600">
                        Dernières alertes reçues par le
                        SOC
                      </p>
                    </div>

                    {hasPermission(
                      "ALERT_READ"
                    ) && (
                      <a
                        href="/alerts"
                        className="flex items-center gap-1 text-[12px] font-medium text-cyan-400 transition-colors hover:text-cyan-300"
                      >
                        Voir toutes les alertes

                        <ChevronRight
                          className="h-3.5 w-3.5"
                          strokeWidth={2}
                        />
                      </a>
                    )}
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[760px] text-left">
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
                            Temps
                          </th>
                        </tr>
                      </thead>

                      <tbody>
                        {loading ? (
                          <tr>
                            <td
                              colSpan={6}
                              className="px-5 py-10 text-center text-xs text-slate-600"
                            >
                              Chargement des alertes...
                            </td>
                          </tr>
                        ) : recentAlerts.length ===
                          0 ? (
                          <tr>
                            <td
                              colSpan={6}
                              className="px-5 py-10 text-center text-xs text-slate-600"
                            >
                              Aucune alerte récente.
                            </td>
                          </tr>
                        ) : (
                          recentAlerts.map(
                            (alert) => (
                              <tr
                                key={
                                  alert.id_alerte
                                }
                                onClick={() => {
                                  window.location.href = `/alerts/${alert.id_alerte}`;
                                }}
                                className="cursor-pointer border-b border-slate-800/50 transition-colors last:border-0 hover:bg-slate-800/20"
                              >
                                <td className="px-5 py-4 font-mono text-xs text-slate-500">
                                  {alert.identifiant_externe ||
                                    alert.id_alerte
                                      ?.slice?.(
                                        0,
                                        8
                                      ) ||
                                    alert.id_alerte}
                                </td>

                                <td className="px-5 py-4">
                                  <p className="max-w-[320px] truncate text-xs font-medium text-slate-300">
                                    {alert.titre ||
                                      "Alerte sans titre"}
                                  </p>
                                </td>

                                <td className="px-5 py-4 text-xs text-slate-500">
                                  {alert.source_alerte ||
                                    "—"}
                                </td>

                                <td className="px-5 py-4">
                                  <span
                                    className={`rounded-md border px-2 py-1 text-[10px] font-semibold ${severityClass(
                                      alert.severite
                                    )}`}
                                  >
                                    {alert.severite ||
                                      "UNKNOWN"}
                                  </span>
                                </td>

                                <td className="px-5 py-4">
                                  <span className="text-xs text-slate-500">
                                    {alert.statut ||
                                      "—"}
                                  </span>
                                </td>

                                <td className="px-5 py-4 font-mono text-xs text-slate-600">
                                  {alert.date_creation
                                    ? new Date(
                                        alert.date_creation
                                      ).toLocaleString(
                                        "fr-FR",
                                        {
                                          day: "2-digit",
                                          month: "2-digit",
                                          hour: "2-digit",
                                          minute:
                                            "2-digit",
                                        }
                                      )
                                    : "—"}
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
            </main>
          </div>
        </div>
      )}
    </AuthGuard>
  );
}