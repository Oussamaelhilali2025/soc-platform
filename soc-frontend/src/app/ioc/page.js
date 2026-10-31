"use client";

import AuthGuard from "@/components/auth/AuthGuard";
import { useRBAC } from "@/components/auth/RBACContext";
import { useEffect, useMemo, useState } from "react";
import { getIOCs } from "@/lib/api";

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
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  Copy,
  Check,
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

const typeStyles = {
  IP: {
    text: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/20",
  },
  DOMAIN: {
    text: "text-violet-400",
    bg: "bg-violet-500/10",
    border: "border-violet-500/20",
  },
  URL: {
    text: "text-amber-400",
    bg: "bg-amber-500/10",
    border: "border-amber-500/20",
  },
  HASH_MD5: {
    text: "text-rose-400",
    bg: "bg-rose-500/10",
    border: "border-rose-500/20",
  },
  HASH_SHA1: {
    text: "text-orange-400",
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
  },
  HASH_SHA256: {
    text: "text-pink-400",
    bg: "bg-pink-500/10",
    border: "border-pink-500/20",
  },
  FILE: {
    text: "text-emerald-400",
    bg: "bg-emerald-500/10",
    border: "border-emerald-500/20",
  },
  EMAIL: {
    text: "text-blue-400",
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
  },
};

function getTypeStyle(type) {
  return (
    typeStyles[type] || {
      text: "text-slate-400",
      bg: "bg-slate-500/10",
      border: "border-slate-600/30",
    }
  );
}

function formatDate(value) {
  if (!value) {
    return "—";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "—";
  }

  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatType(type) {
  if (!type) {
    return "NON CLASSÉ";
  }

  return type;
}

function truncateValue(value, maxLength = 70) {
  if (!value) {
    return "—";
  }

  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength)}...`;
}

export default function IOCPage() {
  const {
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadIOC = hasPermission("IOC_READ");

  const [iocs, setIocs] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [pages, setPages] = useState(1);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [copiedId, setCopiedId] = useState(null);

  async function loadIOCs(targetPage = page) {
    if (!canReadIOC) {
      return;
    }

    try {
      setRefreshing(true);
      setError("");

      const data = await getIOCs(targetPage, pageSize);

      const items = Array.isArray(data?.items)
        ? data.items
        : [];

      setIocs(items);
      setTotal(Number(data?.total ?? 0));
      setPages(Number(data?.pages ?? 1));
      setLastUpdated(new Date());
    } catch (err) {
      console.error("Erreur chargement IOC :", err);

      setError(
        err?.message ||
          "Impossible de charger les indicateurs de compromission."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }

  useEffect(() => {
    if (!rbacLoading && canReadIOC) {
      loadIOCs(page);
    }
  }, [page, canReadIOC, rbacLoading]);

  const filteredIOCs = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();

    return iocs.filter((ioc) => {
      const matchesSearch =
        !normalizedSearch ||
        String(ioc.valeur || "")
          .toLowerCase()
          .includes(normalizedSearch) ||
        String(ioc.type_ioc || "")
          .toLowerCase()
          .includes(normalizedSearch);

      const matchesType =
        typeFilter === "ALL" ||
        ioc.type_ioc === typeFilter;

      return matchesSearch && matchesType;
    });
  }, [iocs, search, typeFilter]);

  const availableTypes = useMemo(() => {
    const types = iocs
      .map((ioc) => ioc.type_ioc)
      .filter(Boolean);

    return [...new Set(types)].sort();
  }, [iocs]);

  function handleSearchChange(event) {
    setSearch(event.target.value);
  }

  function handleTypeChange(event) {
    setTypeFilter(event.target.value);
  }

  function handlePreviousPage() {
    if (page > 1) {
      setPage((current) => current - 1);
    }
  }

  function handleNextPage() {
    if (page < pages) {
      setPage((current) => current + 1);
    }
  }

  function handleCopy(ioc) {
    if (!ioc?.valeur) {
      return;
    }

    navigator.clipboard
      .writeText(ioc.valeur)
      .then(() => {
        setCopiedId(ioc.id_ioc);

        setTimeout(() => {
          setCopiedId(null);
        }, 1500);
      })
      .catch((err) => {
        console.error("Erreur copie IOC :", err);
      });
  }

  function handleIOCClick(id) {
    if (!id || !canReadIOC) {
      return;
    }

    window.location.href = `/ioc/${id}`;
  }

  if (rbacLoading) {
    return (
      <AuthGuard>
        <div className="flex min-h-screen items-center justify-center bg-[#080b12] text-slate-200">
          <div className="flex items-center gap-3 text-sm text-slate-500">
            <RefreshCw className="h-4 w-4 animate-spin" />
            Vérification des permissions...
          </div>
        </div>
      </AuthGuard>
    );
  }

  if (!canReadIOC) {
    return (
      <AuthGuard>
        <div className="min-h-screen bg-[#080b12] p-6 text-slate-200">
          <div className="mx-auto flex min-h-[80vh] max-w-2xl items-center justify-center">
            <div className="w-full rounded-2xl border border-rose-500/20 bg-rose-500/5 p-6">
              <div className="text-sm font-semibold text-rose-400">
                Accès refusé
              </div>

              <div className="mt-2 text-sm text-slate-500">
                Votre compte ne possède pas la permission nécessaire
                pour consulter les indicateurs de compromission.
              </div>

              <button
                type="button"
                onClick={() => window.history.back()}
                className="mt-4 rounded-lg border border-slate-800 px-4 py-2 text-sm font-medium text-slate-300 transition-colors hover:bg-white/[0.04]"
              >
                Retour
              </button>
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  return (
    <AuthGuard>
      <div
        className="flex min-h-screen bg-[#080b12] text-slate-200"
        style={{
          backgroundImage:
            "radial-gradient(ellipse 80% 50% at 50% -10%, rgba(34,211,238,0.06), transparent), linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)",
          backgroundSize:
            "auto, 44px 44px, 44px 44px",
        }}
      >
        {/* ===================================================== */}
        {/* SIDEBAR                                               */}
        {/* ===================================================== */}

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
                (item) =>
                  item.permission
                    ? hasPermission(item.permission)
                    : false
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
                    const isActive = item.href === "/ioc";

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

            {hasPermission("ROLE_MANAGE") && (
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

        {/* ===================================================== */}
        {/* MAIN                                                   */}
        {/* ===================================================== */}

        <main className="min-w-0 flex-1">
          {/* HEADER */}

          <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-800/80 bg-[#0a0e17]/80 px-6 backdrop-blur-md">
            <div>
              <h1 className="text-[15px] font-semibold text-white">
                Indicateurs de compromission
              </h1>

              <p className="text-[11px] text-slate-500">
                Gestion et analyse des IOC détectés par le SOC
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

              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-500/15 text-xs font-semibold text-cyan-400">
                  A
                </div>

                <div className="hidden sm:block">
                  <p className="text-xs font-medium text-white">
                    Administrateur
                  </p>

                  <p className="font-mono text-[10px] text-slate-600">
                    ADMIN
                  </p>
                </div>
              </div>
            </div>
          </header>

          {/* ===================================================== */}
          {/* CONTENT                                               */}
          {/* ===================================================== */}

          <div className="p-6">
            {/* PAGE TITLE */}

            <div className="mb-6 flex flex-col justify-between gap-4 md:flex-row md:items-end">
              <div>
                <h2 className="text-xl font-semibold tracking-tight text-white">
                  IOC
                </h2>

                <p className="mt-1 text-[13px] text-slate-500">
                  Indicateurs de compromission extraits des événements de
                  sécurité.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 rounded-md border border-slate-800 bg-slate-950/40 px-3 py-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

                <span className="text-[10px] text-slate-500">
                  Base IOC
                </span>

                <span className="h-3 w-px bg-slate-800" />

                <span className="font-mono text-[10px] text-slate-400">
                  {total.toLocaleString("fr-FR")} IOC
                </span>

                <span className="h-3 w-px bg-slate-800" />

                <button
                  type="button"
                  onClick={() => loadIOCs(page)}
                  disabled={refreshing}
                  className="flex items-center gap-1.5 text-[10px] font-medium text-slate-400 transition-colors hover:text-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <RefreshCw
                    size={11}
                    className={
                      refreshing ? "animate-spin" : ""
                    }
                  />

                  {refreshing
                    ? "Actualisation..."
                    : "Actualiser"}
                </button>
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

                <button
                  type="button"
                  onClick={() => loadIOCs(page)}
                  disabled={refreshing}
                  className="shrink-0 text-[10px] font-medium text-rose-400 transition-colors hover:text-rose-300 disabled:opacity-50"
                >
                  Réessayer
                </button>
              </div>
            )}

            {/* ================================================= */}
            {/* SUMMARY CARDS                                    */}
            {/* ================================================= */}

            <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {/* TOTAL */}

              <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                <span className="absolute inset-x-0 top-0 h-[2px] bg-violet-500" />

                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-[13px] text-slate-500">
                      IOC détectés
                    </p>

                    <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white">
                      {total.toLocaleString("fr-FR")}
                    </p>

                    <p className="mt-2 text-[11px] text-slate-600">
                      Total enregistré
                    </p>
                  </div>

                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-violet-500/10 ring-1 ring-inset ring-violet-500/20">
                    <Fingerprint
                      className="h-4 w-4 text-violet-400"
                      strokeWidth={2}
                    />
                  </div>
                </div>
              </div>

              {/* PAGE */}

              <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                <span className="absolute inset-x-0 top-0 h-[2px] bg-cyan-500" />

                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-[13px] text-slate-500">
                      Page actuelle
                    </p>

                    <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white">
                      {page}
                    </p>

                    <p className="mt-2 text-[11px] text-slate-600">
                      sur {pages} pages
                    </p>
                  </div>

                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-cyan-500/10 ring-1 ring-inset ring-cyan-500/20">
                    <RefreshCw
                      className="h-4 w-4 text-cyan-400"
                      strokeWidth={2}
                    />
                  </div>
                </div>
              </div>

              {/* IOC AFFICHÉS */}

              <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                <span className="absolute inset-x-0 top-0 h-[2px] bg-emerald-500" />

                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-[13px] text-slate-500">
                      IOC affichés
                    </p>

                    <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white">
                      {filteredIOCs.length}
                    </p>

                    <p className="mt-2 text-[11px] text-slate-600">
                      Après filtrage
                    </p>
                  </div>

                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-emerald-500/10 ring-1 ring-inset ring-emerald-500/20">
                    <ShieldCheck
                      className="h-4 w-4 text-emerald-400"
                      strokeWidth={2}
                    />
                  </div>
                </div>
              </div>

              {/* TYPES */}

              <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19] p-5">
                <span className="absolute inset-x-0 top-0 h-[2px] bg-amber-500" />

                <div className="flex items-start justify-between">
                  <div>
                    <p className="text-[13px] text-slate-500">
                      Types détectés
                    </p>

                    <p className="mt-2 font-mono text-[28px] font-semibold leading-none tracking-tight text-white">
                      {availableTypes.length}
                    </p>

                    <p className="mt-2 text-[11px] text-slate-600">
                      Sur la page actuelle
                    </p>
                  </div>

                  <div className="flex h-9 w-9 items-center justify-center rounded-md bg-amber-500/10 ring-1 ring-inset ring-amber-500/20">
                    <AlertTriangle
                      className="h-4 w-4 text-amber-400"
                      strokeWidth={2}
                    />
                  </div>
                </div>
              </div>
            </div>

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
                      onChange={handleSearchChange}
                      placeholder="Rechercher un IOC ou un type..."
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
                    value={typeFilter}
                    onChange={handleTypeChange}
                    className="rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400 outline-none focus:border-cyan-500/40"
                  >
                    <option value="ALL">
                      Tous les types
                    </option>

                    {availableTypes.map((type) => (
                      <option key={type} value={type}>
                        {formatType(type)}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="text-[10px] text-slate-600">
                  {filteredIOCs.length} résultat
                  {filteredIOCs.length !== 1 ? "s" : ""}
                </div>
              </div>
            </div>

            {/* IOC TABLE */}

            <div className="overflow-hidden rounded-lg border border-slate-800 bg-[#0b0f19]">
              <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4">
                <div>
                  <h3 className="text-[13px] font-semibold text-white">
                    Indicateurs détectés
                  </h3>

                  <p className="mt-1 text-[11px] text-slate-600">
                    Page {page} sur {pages}
                  </p>
                </div>

                <div className="font-mono text-[10px] text-slate-600">
                  {pageSize} / page
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full min-w-[1050px] text-left">
                  <thead>
                    <tr className="border-b border-slate-800/80 text-[10px] text-slate-600">
                      <th className="px-5 py-3 font-medium">
                        Type
                      </th>

                      <th className="px-5 py-3 font-medium">
                        Valeur
                      </th>

                      <th className="px-5 py-3 font-medium">
                        Statut
                      </th>

                      <th className="px-5 py-3 font-medium">
                        Première observation
                      </th>

                      <th className="px-5 py-3 font-medium">
                        Dernière observation
                      </th>

                      <th className="px-5 py-3 text-right font-medium">
                        Action
                      </th>
                    </tr>
                  </thead>

                  <tbody>
                    {loading ? (
                      <tr>
                        <td
                          colSpan={6}
                          className="px-5 py-14 text-center text-xs text-slate-600"
                        >
                          Chargement des indicateurs...
                        </td>
                      </tr>
                    ) : filteredIOCs.length === 0 ? (
                      <tr>
                        <td
                          colSpan={6}
                          className="px-5 py-14 text-center"
                        >
                          <Fingerprint className="mx-auto mb-3 h-7 w-7 text-slate-700" />

                          <p className="text-xs text-slate-500">
                            Aucun IOC trouvé.
                          </p>

                          {(search ||
                            typeFilter !== "ALL") && (
                            <p className="mt-1 text-[10px] text-slate-700">
                              Modifiez les critères de recherche.
                            </p>
                          )}
                        </td>
                      </tr>
                    ) : (
                      filteredIOCs.map((ioc) => {
                        const style = getTypeStyle(
                          ioc.type_ioc
                        );

                        return (
                          <tr
                            key={ioc.id_ioc}
                            onClick={() =>
                              handleIOCClick(ioc.id_ioc)
                            }
                            className="cursor-pointer border-b border-slate-800/50 transition-colors last:border-0 hover:bg-slate-800/20"
                          >
                            <td className="px-5 py-4">
                              <span
                                className={`inline-flex rounded-md border px-2 py-1 text-[10px] font-semibold ${style.border} ${style.bg} ${style.text}`}
                              >
                                {formatType(ioc.type_ioc)}
                              </span>
                            </td>

                            <td className="max-w-[430px] px-5 py-4">
                              <div className="flex items-center gap-2">
                                <p
                                  className="min-w-0 truncate font-mono text-xs text-slate-300"
                                  title={ioc.valeur}
                                >
                                  {truncateValue(
                                    ioc.valeur
                                  )}
                                </p>
                              </div>
                            </td>

                            <td className="px-5 py-4">
                              <span className="inline-flex items-center gap-1.5 text-[10px] font-medium text-emerald-400">
                                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />

                                {ioc.is_ioc
                                  ? "IOC"
                                  : "Non IOC"}
                              </span>
                            </td>

                            <td className="px-5 py-4 font-mono text-[10px] text-slate-500">
                              {formatDate(
                                ioc.date_premiere_observation
                              )}
                            </td>

                            <td className="px-5 py-4 font-mono text-[10px] text-slate-500">
                              {formatDate(
                                ioc.date_derniere_observation
                              )}
                            </td>

                            <td className="px-5 py-4 text-right">
                              <button
                                type="button"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  handleCopy(ioc);
                                }}
                                title="Copier la valeur"
                                className="inline-flex h-7 w-7 items-center justify-center rounded-md border border-slate-800 bg-slate-950/50 text-slate-600 transition-colors hover:border-slate-700 hover:text-cyan-400"
                              >
                                {copiedId ===
                                ioc.id_ioc ? (
                                  <Check
                                    className="h-3.5 w-3.5 text-emerald-400"
                                    strokeWidth={2}
                                  />
                                ) : (
                                  <Copy
                                    className="h-3.5 w-3.5"
                                    strokeWidth={2}
                                  />
                                )}
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* PAGINATION */}

              <div className="flex flex-col gap-3 border-t border-slate-800/80 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="text-[10px] text-slate-600">
                  Affichage de la page{" "}
                  <span className="font-mono text-slate-400">
                    {page}
                  </span>{" "}
                  sur{" "}
                  <span className="font-mono text-slate-400">
                    {pages}
                  </span>
                  {" · "}
                  <span className="font-mono text-slate-400">
                    {total}
                  </span>{" "}
                  IOC au total
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handlePreviousPage}
                    disabled={page <= 1 || loading}
                    className="flex h-8 items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/50 px-3 text-[10px] text-slate-500 transition-colors hover:border-slate-700 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-30"
                  >
                    <ChevronLeft
                      className="h-3.5 w-3.5"
                      strokeWidth={2}
                    />
                    Précédent
                  </button>

                  <div className="flex items-center gap-1">
                    {Array.from(
                      { length: pages },
                      (_, index) => index + 1
                    ).map((pageNumber) => (
                      <button
                        key={pageNumber}
                        type="button"
                        onClick={() =>
                          setPage(pageNumber)
                        }
                        className={`flex h-8 min-w-8 items-center justify-center rounded-md border px-2 font-mono text-[10px] transition-colors ${
                          pageNumber === page
                            ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-400"
                            : "border-transparent text-slate-600 hover:border-slate-800 hover:text-slate-300"
                        }`}
                      >
                        {pageNumber}
                      </button>
                    ))}
                  </div>

                  <button
                    type="button"
                    onClick={handleNextPage}
                    disabled={page >= pages || loading}
                    className="flex h-8 items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/50 px-3 text-[10px] text-slate-500 transition-colors hover:border-slate-700 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-30"
                  >
                    Suivant

                    <ChevronRight
                      className="h-3.5 w-3.5"
                      strokeWidth={2}
                    />
                  </button>
                </div>
              </div>
            </div>

            {/* LAST UPDATE */}

            <div className="mt-4 flex justify-end">
              <span className="text-[10px] text-slate-700">
                Dernière mise à jour :{" "}
                <span className="font-mono text-slate-600">
                  {lastUpdated
                    ? new Intl.DateTimeFormat(
                        "fr-FR",
                        {
                          hour: "2-digit",
                          minute: "2-digit",
                          second: "2-digit",
                        }
                      ).format(lastUpdated)
                    : "—"}
                </span>
              </span>
            </div>
          </div>
        </main>
      </div>
    </AuthGuard>
  );
}