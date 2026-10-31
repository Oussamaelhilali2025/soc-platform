"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Ticket,
  RefreshCw,
  ExternalLink,
  Search,
  Eye,
  X,
  Clock,
  CheckCircle2,
  AlertCircle,
  ListChecks,
} from "lucide-react";

const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const GLPI_URL =
  process.env.NEXT_PUBLIC_GLPI_URL || "http://localhost/glpi";

const STATUS_MAP = {
  1: {
    label: "Nouveau",
    className:
      "bg-blue-500/10 text-blue-400 border-blue-500/20",
  },
  2: {
    label: "En cours",
    className:
      "bg-amber-500/10 text-amber-400 border-amber-500/20",
  },
  3: {
    label: "Planifié",
    className:
      "bg-orange-500/10 text-orange-400 border-orange-500/20",
  },
  4: {
    label: "En attente",
    className:
      "bg-purple-500/10 text-purple-400 border-purple-500/20",
  },
  5: {
    label: "Résolu",
    className:
      "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  },
  6: {
    label: "Clos",
    className:
      "bg-slate-500/10 text-slate-400 border-slate-500/20",
  },
};

const PRIORITY_MAP = {
  1: "Très basse",
  2: "Basse",
  3: "Moyenne",
  4: "Haute",
  5: "Très haute",
  6: "Majeure",
};

function getStatus(status) {
  return (
    STATUS_MAP[status] || {
      label: `Statut ${status}`,
      className:
        "bg-slate-500/10 text-slate-400 border-slate-500/20",
    }
  );
}

function getPriorityStyle(priority) {
  switch (Number(priority)) {
    case 6:
    case 5:
      return "text-rose-400";
    case 4:
      return "text-orange-400";
    case 3:
      return "text-yellow-400";
    case 2:
      return "text-blue-400";
    default:
      return "text-slate-400";
  }
}

function formatDate(date) {
  if (!date) return "-";

  try {
    return new Date(date).toLocaleString("fr-FR");
  } catch {
    return date;
  }
}

function cleanContent(content) {
  if (!content) return "-";

  return content
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .trim();
}

export default function GLPIPage() {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [selectedTicket, setSelectedTicket] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");

  async function loadTickets() {
    try {
      setLoading(true);
      setError(null);

      const response = await fetch(`${API_URL}/glpi/tickets`, {
        cache: "no-store",
      });

      if (!response.ok) {
        throw new Error(
          "Impossible de récupérer les tickets GLPI"
        );
      }

      const data = await response.json();

      setTickets(Array.isArray(data.tickets) ? data.tickets : []);
    } catch (err) {
      console.error("Erreur GLPI :", err);

      setError(
        err.message || "Erreur lors du chargement des tickets"
      );
    } finally {
      setLoading(false);
    }
  }

  async function loadTicket(ticketId) {
    try {
      setDetailLoading(true);

      const response = await fetch(
        `${API_URL}/glpi/tickets/${ticketId}`,
        {
          cache: "no-store",
        }
      );

      if (!response.ok) {
        throw new Error(
          "Impossible de récupérer le ticket"
        );
      }

      const data = await response.json();

      setSelectedTicket(data.ticket);
    } catch (err) {
      console.error("Erreur ticket GLPI :", err);

      alert(
        err.message || "Erreur lors du chargement du ticket"
      );
    } finally {
      setDetailLoading(false);
    }
  }

  useEffect(() => {
    loadTickets();
  }, []);

  const filteredTickets = tickets.filter((ticket) => {
    const value = search.toLowerCase().trim();

    const matchesSearch =
      !value ||
      String(ticket.id).includes(value) ||
      (ticket.name || "").toLowerCase().includes(value) ||
      (ticket.content || "").toLowerCase().includes(value);

    const matchesStatus =
      statusFilter === "ALL" ||
      String(ticket.status) === String(statusFilter);

    return matchesSearch && matchesStatus;
  });

  const total = tickets.length;

  const newTickets = tickets.filter(
    (ticket) => Number(ticket.status) === 1
  ).length;

  const pendingTickets = tickets.filter((ticket) =>
    [2, 3, 4].includes(Number(ticket.status))
  ).length;

  const resolvedTickets = tickets.filter((ticket) =>
    [5, 6].includes(Number(ticket.status))
  ).length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="p-6 space-y-6">

        {/* ===================================================== */}
        {/* HEADER */}
        {/* ===================================================== */}

        <div className="space-y-4">

          {/* Retour Dashboard */}
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Retour au dashboard
          </Link>

          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">

            <div className="flex items-center gap-3">

              <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                <Ticket className="w-5 h-5 text-cyan-400" />
              </div>

              <div>
                <h1 className="text-2xl font-bold text-white">
                  Tickets GLPI
                </h1>

                <p className="text-sm text-slate-400 mt-1">
                  Suivi des demandes et de la remédiation des
                  vulnérabilités
                </p>
              </div>

            </div>

            <div className="flex flex-wrap gap-2">

              <button
                onClick={loadTickets}
                disabled={loading}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 text-sm hover:bg-slate-700 disabled:opacity-50 transition-colors"
              >
                <RefreshCw
                  className={`w-4 h-4 ${
                    loading ? "animate-spin" : ""
                  }`}
                />

                {loading
                  ? "Actualisation..."
                  : "Actualiser"}
              </button>

              <a
                href={GLPI_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm hover:bg-cyan-500/20 transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                Ouvrir GLPI
              </a>

            </div>
          </div>
        </div>

        {/* ===================================================== */}
        {/* ERROR */}
        {/* ===================================================== */}

        {error && (
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/10 p-4 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-400 mt-0.5" />

            <div>
              <p className="text-sm font-medium text-rose-300">
                Erreur GLPI
              </p>

              <p className="text-sm text-rose-400/80 mt-1">
                {error}
              </p>
            </div>
          </div>
        )}

        {/* ===================================================== */}
        {/* KPI */}
        {/* ===================================================== */}

        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

          {/* Total */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-sm text-slate-400">
                  Total tickets
                </p>

                <p className="text-3xl font-bold text-white mt-2">
                  {total}
                </p>
              </div>

              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                <ListChecks className="w-5 h-5 text-cyan-400" />
              </div>

            </div>
          </div>

          {/* Nouveaux */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-sm text-slate-400">
                  Nouveaux
                </p>

                <p className="text-3xl font-bold text-blue-400 mt-2">
                  {newTickets}
                </p>
              </div>

              <div className="w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
                <Ticket className="w-5 h-5 text-blue-400" />
              </div>

            </div>
          </div>

          {/* En traitement */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-sm text-slate-400">
                  En traitement
                </p>

                <p className="text-3xl font-bold text-amber-400 mt-2">
                  {pendingTickets}
                </p>
              </div>

              <div className="w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
                <Clock className="w-5 h-5 text-amber-400" />
              </div>

            </div>
          </div>

          {/* Résolus */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">

              <div>
                <p className="text-sm text-slate-400">
                  Résolus / clos
                </p>

                <p className="text-3xl font-bold text-emerald-400 mt-2">
                  {resolvedTickets}
                </p>
              </div>

              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              </div>

            </div>
          </div>

        </div>

        {/* ===================================================== */}
        {/* SEARCH + FILTER */}
        {/* ===================================================== */}

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">

          <div className="flex flex-col lg:flex-row gap-3">

            <div className="relative flex-1">

              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />

              <input
                type="text"
                placeholder="Rechercher par ID, titre ou contenu..."
                value={search}
                onChange={(e) =>
                  setSearch(e.target.value)
                }
                className="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/30"
              />

            </div>

            <select
              value={statusFilter}
              onChange={(e) =>
                setStatusFilter(e.target.value)
              }
              className="lg:w-52 px-4 py-2.5 bg-slate-950 border border-slate-800 rounded-lg text-sm text-slate-300 outline-none focus:border-cyan-500/50"
            >
              <option value="ALL">
                Tous les statuts
              </option>

              <option value="1">
                Nouveau
              </option>

              <option value="2">
                En cours
              </option>

              <option value="3">
                Planifié
              </option>

              <option value="4">
                En attente
              </option>

              <option value="5">
                Résolu
              </option>

              <option value="6">
                Clos
              </option>
            </select>

          </div>
        </div>

        {/* ===================================================== */}
        {/* TABLE */}
        {/* ===================================================== */}

        <div className="rounded-xl border border-slate-800 bg-slate-900/70 overflow-hidden">

          <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">

            <div>
              <h2 className="font-semibold text-white">
                Liste des tickets
              </h2>

              <p className="text-sm text-slate-500 mt-1">
                {filteredTickets.length} ticket
                {filteredTickets.length !== 1 ? "s" : ""}
              </p>
            </div>

            <Ticket className="w-5 h-5 text-slate-600" />

          </div>

          {loading ? (

            <div className="p-12 text-center">

              <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />

              <p className="text-sm text-slate-500 mt-3">
                Chargement des tickets...
              </p>

            </div>

          ) : filteredTickets.length === 0 ? (

            <div className="p-12 text-center">

              <Ticket className="w-8 h-8 text-slate-700 mx-auto" />

              <p className="text-sm text-slate-500 mt-3">
                Aucun ticket trouvé.
              </p>

            </div>

          ) : (

            <div className="overflow-x-auto">

              <table className="w-full text-sm">

                <thead className="bg-slate-950/70 border-b border-slate-800">

                  <tr>

                    <th className="text-left px-5 py-3 font-medium text-slate-500">
                      ID
                    </th>

                    <th className="text-left px-5 py-3 font-medium text-slate-500">
                      Ticket
                    </th>

                    <th className="text-left px-5 py-3 font-medium text-slate-500">
                      Priorité
                    </th>

                    <th className="text-left px-5 py-3 font-medium text-slate-500">
                      Statut
                    </th>

                    <th className="text-left px-5 py-3 font-medium text-slate-500">
                      Dernière modification
                    </th>

                    <th className="text-right px-5 py-3 font-medium text-slate-500">
                      Action
                    </th>

                  </tr>

                </thead>

                <tbody className="divide-y divide-slate-800">

                  {filteredTickets.map((ticket) => {

                    const status = getStatus(
                      ticket.status
                    );

                    const priorityStyle =
                      getPriorityStyle(
                        ticket.priority
                      );

                    return (

                      <tr
                        key={ticket.id}
                        className="hover:bg-slate-800/30 transition-colors"
                      >

                        <td className="px-5 py-4">

                          <span className="font-mono text-cyan-400">
                            #{ticket.id}
                          </span>

                        </td>

                        <td className="px-5 py-4">

                          <div className="font-medium text-slate-200 max-w-md">
                            {ticket.name ||
                              "Sans titre"}
                          </div>

                          <div className="text-xs text-slate-500 mt-1 truncate max-w-md">
                            {cleanContent(
                              ticket.content
                            ).slice(0, 120)}
                            {cleanContent(
                              ticket.content
                            ).length > 120
                              ? "..."
                              : ""}
                          </div>

                        </td>

                        <td className="px-5 py-4">

                          <span
                            className={`font-medium ${priorityStyle}`}
                          >
                            {PRIORITY_MAP[
                              ticket.priority
                            ] ||
                              `Priorité ${ticket.priority}`}
                          </span>

                        </td>

                        <td className="px-5 py-4">

                          <span
                            className={`inline-flex items-center px-2.5 py-1 rounded-full border text-xs font-medium ${status.className}`}
                          >
                            {status.label}
                          </span>

                        </td>

                        <td className="px-5 py-4 text-slate-500">

                          {formatDate(
                            ticket.date_mod
                          )}

                        </td>

                        <td className="px-5 py-4 text-right">

                          <button
                            onClick={() =>
                              loadTicket(ticket.id)
                            }
                            className="inline-flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
                          >
                            <Eye className="w-4 h-4" />
                            Voir
                          </button>

                        </td>

                      </tr>

                    );
                  })}

                </tbody>

              </table>

            </div>

          )}

        </div>

        {/* ===================================================== */}
        {/* DETAIL MODAL */}
        {/* ===================================================== */}

        {selectedTicket && (

          <div
            className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
            onClick={() =>
              setSelectedTicket(null)
            }
          >

            <div
              className="bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto"
              onClick={(e) =>
                e.stopPropagation()
              }
            >

              {/* Modal header */}

              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">

                <div className="flex items-center gap-3">

                  <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
                    <Ticket className="w-5 h-5 text-cyan-400" />
                  </div>

                  <div>

                    <h2 className="text-lg font-semibold text-white">
                      Ticket #{selectedTicket.id}
                    </h2>

                    <p className="text-sm text-slate-500 mt-1">
                      {selectedTicket.name ||
                        "Sans titre"}
                    </p>

                  </div>

                </div>

                <button
                  onClick={() =>
                    setSelectedTicket(null)
                  }
                  className="w-8 h-8 rounded-lg flex items-center justify-center text-slate-500 hover:text-white hover:bg-slate-800 transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>

              </div>

              {/* Modal body */}

              <div className="p-6 space-y-6">

                {detailLoading ? (

                  <div className="py-12 text-center">

                    <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />

                    <p className="text-sm text-slate-500 mt-3">
                      Chargement du ticket...
                    </p>

                  </div>

                ) : (

                  <>

                    {/* Infos */}

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

                      <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4">

                        <p className="text-xs text-slate-500">
                          Statut
                        </p>

                        <p className="font-medium text-slate-200 mt-2">
                          {
                            getStatus(
                              selectedTicket.status
                            ).label
                          }
                        </p>

                      </div>

                      <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4">

                        <p className="text-xs text-slate-500">
                          Priorité
                        </p>

                        <p
                          className={`font-medium mt-2 ${getPriorityStyle(
                            selectedTicket.priority
                          )}`}
                        >
                          {PRIORITY_MAP[
                            selectedTicket.priority
                          ] ||
                            selectedTicket.priority}
                        </p>

                      </div>

                      <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4">

                        <p className="text-xs text-slate-500">
                          Création
                        </p>

                        <p className="font-medium text-slate-200 mt-2 text-xs">
                          {formatDate(
                            selectedTicket.date_creation
                          )}
                        </p>

                      </div>

                      <div className="rounded-lg bg-slate-950/70 border border-slate-800 p-4">

                        <p className="text-xs text-slate-500">
                          Modification
                        </p>

                        <p className="font-medium text-slate-200 mt-2 text-xs">
                          {formatDate(
                            selectedTicket.date_mod
                          )}
                        </p>

                      </div>

                    </div>

                    {/* Description */}

                    <div>

                      <h3 className="font-semibold text-white mb-2">
                        Description
                      </h3>

                      <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4 text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">
                        {cleanContent(
                          selectedTicket.content
                        ) ||
                          "Aucune description"}
                      </div>

                    </div>

                    {/* Responsable */}

                    <div>

                      <h3 className="font-semibold text-white mb-2">
                        Responsable
                      </h3>

                      <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-4">

                        <p className="text-sm text-slate-400">
                          Utilisateur GLPI
                        </p>

                        <p className="text-sm text-slate-200 mt-1">
                          #
                          {selectedTicket.users_id_recipient ||
                            "-"}
                        </p>

                      </div>

                    </div>

                    {/* Solution */}

                    {selectedTicket.solvedate && (

                      <div>

                        <h3 className="font-semibold text-white mb-2">
                          Résolution
                        </h3>

                        <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-4">

                          <p className="text-sm text-emerald-300">
                            Ticket résolu le{" "}
                            {formatDate(
                              selectedTicket.solvedate
                            )}
                          </p>

                        </div>

                      </div>

                    )}

                    {/* Actions */}

                    <div className="flex flex-wrap justify-end gap-3 pt-4 border-t border-slate-800">

                      <a
                        href={`${GLPI_URL}/front/ticket.form.php?id=${selectedTicket.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-sm hover:bg-cyan-500/20 transition-colors"
                      >
                        <ExternalLink className="w-4 h-4" />
                        Ouvrir dans GLPI
                      </a>

                      <button
                        onClick={() =>
                          setSelectedTicket(null)
                        }
                        className="px-4 py-2 rounded-lg border border-slate-700 bg-slate-800 text-slate-300 text-sm hover:bg-slate-700 transition-colors"
                      >
                        Fermer
                      </button>

                    </div>

                  </>

                )}

              </div>

            </div>

          </div>

        )}

      </div>
    </div>
  );
}