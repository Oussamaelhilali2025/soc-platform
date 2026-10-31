"use client";

import { useEffect, useState } from "react";
import {
  getAdminUsers,
  getAdminRoles,
  getAdminPermissions,
  createAdminUser,
  updateAdminUserStatus,
  assignAdminUserRole,
} from "@/lib/api";

function formatDate(value) {
  if (!value) return "—";

  try {
    return new Date(value).toLocaleString("fr-FR");
  } catch {
    return value;
  }
}

function StatusBadge({ status }) {
  const styles = {
    ACTIVE:
      "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",

    INACTIVE:
      "border-slate-500/30 bg-slate-500/10 text-slate-400",

    LOCKED:
      "border-rose-500/30 bg-rose-500/10 text-rose-400",
  };

  return (
    <span
      className={`inline-flex rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide ${
        styles[status] ||
        "border-slate-500/30 bg-slate-500/10 text-slate-400"
      }`}
    >
      {status || "UNKNOWN"}
    </span>
  );
}

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [permissions, setPermissions] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [activeTab, setActiveTab] = useState("users");

  const [savingUser, setSavingUser] = useState(null);

  /* ============================================================
     CREATION UTILISATEUR
  ============================================================ */

  const [showCreateUser, setShowCreateUser] = useState(false);
  const [creatingUser, setCreatingUser] = useState(false);

  const [newUser, setNewUser] = useState({
    nom_utilisateur: "",
    email: "",
    nom: "",
    prenom: "",
    mot_de_passe: "",
    id_role: "",
    statut: "ACTIVE",
  });

  /* ============================================================
     CHARGEMENT ADMIN
  ============================================================ */

  async function loadAdminData() {
    try {
      setLoading(true);
      setError("");

      const [
        usersData,
        rolesData,
        permissionsData,
      ] = await Promise.all([
        getAdminUsers(),
        getAdminRoles(),
        getAdminPermissions(),
      ]);

      setUsers(
        Array.isArray(usersData)
          ? usersData
          : []
      );

      setRoles(
        Array.isArray(rolesData)
          ? rolesData
          : []
      );

      setPermissions(
        Array.isArray(permissionsData)
          ? permissionsData
          : []
      );
    } catch (err) {
      console.error("ADMIN API ERROR", err);

      setError(
        err?.message ||
          "Impossible de charger les données d'administration."
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAdminData();
  }, []);

  /* ============================================================
     CREER UTILISATEUR
  ============================================================ */

  async function handleCreateUser(event) {
    event.preventDefault();

    try {
      setCreatingUser(true);
      setError("");

      if (!newUser.prenom.trim()) {
        setError("Le prénom est obligatoire.");
        return;
      }

      if (!newUser.nom.trim()) {
        setError("Le nom est obligatoire.");
        return;
      }

      if (!newUser.nom_utilisateur.trim()) {
        setError(
          "Le nom d'utilisateur est obligatoire."
        );
        return;
      }

      if (!newUser.email.trim()) {
        setError("L'adresse email est obligatoire.");
        return;
      }

      if (!newUser.mot_de_passe) {
        setError("Le mot de passe est obligatoire.");
        return;
      }

      if (newUser.mot_de_passe.length < 8) {
        setError(
          "Le mot de passe doit contenir au moins 8 caractères."
        );
        return;
      }

      if (!newUser.id_role) {
        setError("Veuillez sélectionner un rôle.");
        return;
      }

      await createAdminUser({
        nom_utilisateur:
          newUser.nom_utilisateur.trim(),

        email: newUser.email.trim(),

        nom: newUser.nom.trim(),

        prenom: newUser.prenom.trim(),

        mot_de_passe:
          newUser.mot_de_passe,

        id_role: newUser.id_role,

        statut: newUser.statut,
      });

      setNewUser({
        nom_utilisateur: "",
        email: "",
        nom: "",
        prenom: "",
        mot_de_passe: "",
        id_role: "",
        statut: "ACTIVE",
      });

      setShowCreateUser(false);

      await loadAdminData();
    } catch (err) {
      console.error("CREATE USER ERROR", err);

      setError(
        err?.message ||
          "Impossible de créer l'utilisateur."
      );
    } finally {
      setCreatingUser(false);
    }
  }

  /* ============================================================
     MODIFIER STATUT
  ============================================================ */

  async function handleStatusChange(user, statut) {
    try {
      setSavingUser(user.id_utilisateur);
      setError("");

      await updateAdminUserStatus(
        user.id_utilisateur,
        statut
      );

      await loadAdminData();
    } catch (err) {
      setError(
        err?.message ||
          "Impossible de modifier le statut de l'utilisateur."
      );
    } finally {
      setSavingUser(null);
    }
  }

  /* ============================================================
     MODIFIER ROLE
  ============================================================ */

  async function handleRoleChange(user, roleId) {
    if (!roleId) return;

    try {
      setSavingUser(user.id_utilisateur);
      setError("");

      await assignAdminUserRole(
        user.id_utilisateur,
        roleId
      );

      await loadAdminData();
    } catch (err) {
      setError(
        err?.message ||
          "Impossible de modifier le rôle de l'utilisateur."
      );
    } finally {
      setSavingUser(null);
    }
  }

  return (
    <main className="min-h-screen bg-[var(--background)] text-[var(--foreground)]">
      <div className="mx-auto max-w-7xl px-6 py-8">

        {/* ==================================================
            HEADER
        ================================================== */}

        <div className="mb-8">
          <p className="text-xs font-medium uppercase tracking-[0.2em] text-cyan-500">
            Administration
          </p>

          <div className="mt-2 flex flex-col justify-between gap-4 md:flex-row md:items-end">
            <div>
              <h1 className="text-2xl font-bold">
                Administration de la plateforme
              </h1>

              <p className="mt-2 text-sm text-[var(--muted)]">
                Gestion des utilisateurs, rôles et permissions
                du SOC.
              </p>
            </div>

            <button
              type="button"
              onClick={loadAdminData}
              disabled={loading}
              className="rounded-lg border border-[var(--border)] bg-white/[0.03] px-4 py-2 text-sm font-medium transition hover:bg-white/[0.06] disabled:opacity-50"
            >
              {loading
                ? "Chargement..."
                : "Actualiser"}
            </button>
          </div>
        </div>

        {/* ==================================================
            ERROR
        ================================================== */}

        {error && (
          <div className="mb-6 rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-400">
            {error}
          </div>
        )}

        {/* ==================================================
            TABS
        ================================================== */}

        <div className="mb-6 flex flex-wrap gap-2 border-b border-[var(--border)] pb-3">

          <button
            type="button"
            onClick={() => setActiveTab("users")}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
              activeTab === "users"
                ? "bg-cyan-500/10 text-cyan-400"
                : "text-[var(--muted)] hover:bg-white/[0.04]"
            }`}
          >
            Utilisateurs
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("roles")}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
              activeTab === "roles"
                ? "bg-cyan-500/10 text-cyan-400"
                : "text-[var(--muted)] hover:bg-white/[0.04]"
            }`}
          >
            Rôles
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("permissions")}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
              activeTab === "permissions"
                ? "bg-cyan-500/10 text-cyan-400"
                : "text-[var(--muted)] hover:bg-white/[0.04]"
            }`}
          >
            Permissions
          </button>

        </div>

        {/* ==================================================
            LOADING
        ================================================== */}

        {loading ? (
          <div className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-8 text-center text-sm text-[var(--muted)]">
            Chargement de l'administration...
          </div>
        ) : (
          <>

            {/* ==================================================
                USERS
            ================================================== */}

            {activeTab === "users" && (
              <section className="overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--card)]">

                {/* HEADER USERS */}

                <div className="flex flex-col justify-between gap-4 border-b border-[var(--border)] px-5 py-4 md:flex-row md:items-center">

                  <div>
                    <h2 className="text-base font-semibold">
                      Utilisateurs
                    </h2>

                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Gestion des comptes et de leurs rôles.
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() =>
                      setShowCreateUser(
                        (value) => !value
                      )
                    }
                    className="rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 transition hover:bg-cyan-400"
                  >
                    {showCreateUser
                      ? "Fermer"
                      : "+ Ajouter un utilisateur"}
                  </button>

                </div>

                {/* ==================================================
                    CREATE USER FORM
                ================================================== */}

                {showCreateUser && (
                  <form
                    onSubmit={handleCreateUser}
                    className="border-b border-[var(--border)] bg-white/[0.02] p-5"
                  >

                    <div className="mb-5">
                      <h3 className="text-sm font-semibold">
                        Ajouter un utilisateur
                      </h3>

                      <p className="mt-1 text-xs text-[var(--muted)]">
                        Créer un nouveau compte et lui
                        attribuer un rôle.
                      </p>
                    </div>

                    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">

                      {/* PRENOM */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Prénom
                        </label>

                        <input
                          type="text"
                          required
                          value={newUser.prenom}
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              prenom:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                          placeholder="Prénom"
                        />
                      </div>

                      {/* NOM */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Nom
                        </label>

                        <input
                          type="text"
                          required
                          value={newUser.nom}
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              nom:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                          placeholder="Nom"
                        />
                      </div>

                      {/* USERNAME */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Nom d'utilisateur
                        </label>

                        <input
                          type="text"
                          required
                          value={
                            newUser.nom_utilisateur
                          }
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              nom_utilisateur:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                          placeholder="ex: jdupont"
                        />
                      </div>

                      {/* EMAIL */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Email
                        </label>

                        <input
                          type="email"
                          required
                          value={newUser.email}
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              email:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                          placeholder="utilisateur@example.com"
                        />
                      </div>

                      {/* PASSWORD */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Mot de passe
                        </label>

                        <input
                          type="password"
                          required
                          minLength={8}
                          value={
                            newUser.mot_de_passe
                          }
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              mot_de_passe:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                          placeholder="Minimum 8 caractères"
                        />
                      </div>

                      {/* ROLE */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Rôle
                        </label>

                        <select
                          required
                          value={newUser.id_role}
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              id_role:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                        >
                          <option
                            value=""
                            className="bg-slate-900"
                          >
                            Sélectionner un rôle
                          </option>

                          {roles.map((role) => (
                            <option
                              key={role.id_role}
                              value={role.id_role}
                              className="bg-slate-900"
                            >
                              {role.nom}
                            </option>
                          ))}
                        </select>
                      </div>

                      {/* STATUT */}

                      <div>
                        <label className="mb-1.5 block text-xs font-medium text-[var(--muted)]">
                          Statut
                        </label>

                        <select
                          value={newUser.statut}
                          onChange={(e) =>
                            setNewUser({
                              ...newUser,
                              statut:
                                e.target.value,
                            })
                          }
                          className="w-full rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2.5 text-sm outline-none focus:border-cyan-500/50"
                        >
                          <option
                            value="ACTIVE"
                            className="bg-slate-900"
                          >
                            Actif
                          </option>

                          <option
                            value="INACTIVE"
                            className="bg-slate-900"
                          >
                            Inactif
                          </option>

                          <option
                            value="LOCKED"
                            className="bg-slate-900"
                          >
                            Verrouillé
                          </option>
                        </select>
                      </div>

                    </div>

                    {/* FORM ACTIONS */}

                    <div className="mt-5 flex justify-end gap-3">

                      <button
                        type="button"
                        onClick={() =>
                          setShowCreateUser(false)
                        }
                        disabled={creatingUser}
                        className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium text-[var(--muted)] transition hover:bg-white/[0.04] disabled:opacity-50"
                      >
                        Annuler
                      </button>

                      <button
                        type="submit"
                        disabled={creatingUser}
                        className="rounded-lg bg-cyan-500 px-5 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {creatingUser
                          ? "Création..."
                          : "Créer l'utilisateur"}
                      </button>

                    </div>

                  </form>
                )}

                {/* ==================================================
                    USERS TABLE
                ================================================== */}

                <div className="overflow-x-auto">

                  <table className="w-full min-w-[900px] text-left">

                    <thead>
                      <tr className="border-b border-[var(--border)] text-[10px] uppercase tracking-wider text-[var(--muted)]">

                        <th className="px-5 py-4">
                          Utilisateur
                        </th>

                        <th className="px-5 py-4">
                          Email
                        </th>

                        <th className="px-5 py-4">
                          Rôle
                        </th>

                        <th className="px-5 py-4">
                          Statut
                        </th>

                        <th className="px-5 py-4">
                          Dernière connexion
                        </th>

                        <th className="px-5 py-4">
                          Actions
                        </th>

                      </tr>
                    </thead>

                    <tbody>

                      {users.map((user) => {

                        const currentRole =
                          user.roles?.[0]
                            ?.id_role || "";

                        const isSaving =
                          savingUser ===
                          user.id_utilisateur;

                        return (
                          <tr
                            key={
                              user.id_utilisateur
                            }
                            className="border-b border-[var(--border)] last:border-0"
                          >

                            {/* UTILISATEUR */}

                            <td className="px-5 py-4">

                              <div className="font-medium">
                                {user.prenom}{" "}
                                {user.nom}
                              </div>

                              <div className="mt-1 text-xs text-[var(--muted)]">
                                @
                                {
                                  user.nom_utilisateur
                                }
                              </div>

                            </td>

                            {/* EMAIL */}

                            <td className="px-5 py-4 text-sm text-[var(--muted)]">
                              {user.email}
                            </td>

                            {/* ROLE */}

                            <td className="px-5 py-4">

                              <select
                                value={currentRole}
                                disabled={isSaving}
                                onChange={(e) =>
                                  handleRoleChange(
                                    user,
                                    e.target.value
                                  )
                                }
                                className="rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2 text-sm outline-none focus:border-cyan-500/50"
                              >

                                {roles.map(
                                  (role) => (
                                    <option
                                      key={
                                        role.id_role
                                      }
                                      value={
                                        role.id_role
                                      }
                                      className="bg-slate-900"
                                    >
                                      {role.nom}
                                    </option>
                                  )
                                )}

                              </select>

                            </td>

                            {/* STATUT */}

                            <td className="px-5 py-4">

                              <StatusBadge
                                status={
                                  user.statut
                                }
                              />

                            </td>

                            {/* DERNIERE CONNEXION */}

                            <td className="px-5 py-4 text-xs text-[var(--muted)]">
                              {formatDate(
                                user.derniere_connexion
                              )}
                            </td>

                            {/* ACTION */}

                            <td className="px-5 py-4">

                              <select
                                value={
                                  user.statut
                                }
                                disabled={isSaving}
                                onChange={(e) =>
                                  handleStatusChange(
                                    user,
                                    e.target.value
                                  )
                                }
                                className="rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2 text-sm outline-none focus:border-cyan-500/50"
                              >

                                <option
                                  value="ACTIVE"
                                  className="bg-slate-900"
                                >
                                  Actif
                                </option>

                                <option
                                  value="INACTIVE"
                                  className="bg-slate-900"
                                >
                                  Inactif
                                </option>

                                <option
                                  value="LOCKED"
                                  className="bg-slate-900"
                                >
                                  Verrouillé
                                </option>

                              </select>

                            </td>

                          </tr>
                        );
                      })}

                    </tbody>

                  </table>

                </div>

                {users.length === 0 && (
                  <div className="p-8 text-center text-sm text-[var(--muted)]">
                    Aucun utilisateur.
                  </div>
                )}

              </section>
            )}

            {/* ==================================================
                ROLES
            ================================================== */}

            {activeTab === "roles" && (
              <section className="rounded-2xl border border-[var(--border)] bg-[var(--card)]">

                <div className="border-b border-[var(--border)] px-5 py-4">

                  <h2 className="text-base font-semibold">
                    Rôles
                  </h2>

                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Rôles disponibles et permissions associées.
                  </p>

                </div>

                <div className="grid gap-4 p-5 lg:grid-cols-3">

                  {roles.map((role) => (
                    <div
                      key={role.id_role}
                      className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-5"
                    >

                      <div className="flex items-center justify-between gap-3">

                        <h3 className="font-semibold">
                          {role.nom}
                        </h3>

                        <span className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-2 py-1 text-[10px] text-cyan-400">
                          {role.permissions?.length ||
                            0}{" "}
                          permissions
                        </span>

                      </div>

                      <p className="mt-2 text-sm text-[var(--muted)]">
                        {role.description ||
                          "Aucune description."}
                      </p>

                      <div className="mt-4 space-y-2">

                        {role.permissions?.map(
                          (permission) => (
                            <div
                              key={
                                permission.id_permission
                              }
                              className="rounded-lg border border-[var(--border)] bg-black/10 px-3 py-2"
                            >

                              <div className="text-xs font-medium text-cyan-400">
                                {permission.code}
                              </div>

                              <div className="mt-1 text-[11px] text-[var(--muted)]">
                                {
                                  permission.description
                                }
                              </div>

                            </div>
                          )
                        )}

                      </div>

                    </div>
                  ))}

                </div>

              </section>
            )}

            {/* ==================================================
                PERMISSIONS
            ================================================== */}

            {activeTab === "permissions" && (
              <section className="rounded-2xl border border-[var(--border)] bg-[var(--card)]">

                <div className="border-b border-[var(--border)] px-5 py-4">

                  <h2 className="text-base font-semibold">
                    Permissions
                  </h2>

                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Permissions disponibles dans le système RBAC.
                  </p>

                </div>

                <div className="grid gap-3 p-5 md:grid-cols-2 lg:grid-cols-3">

                  {permissions.map(
                    (permission) => (
                      <div
                        key={
                          permission.id_permission
                        }
                        className="rounded-xl border border-[var(--border)] bg-white/[0.02] p-4"
                      >

                        <div className="text-sm font-semibold text-cyan-400">
                          {permission.code}
                        </div>

                        <p className="mt-1 text-xs leading-5 text-[var(--muted)]">
                          {
                            permission.description
                          }
                        </p>

                      </div>
                    )
                  )}

                </div>

              </section>
            )}

          </>
        )}

      </div>
    </main>
  );
}