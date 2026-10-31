const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function login(username, password) {
  const body = new URLSearchParams();

  body.append("username", username);
  body.append("password", password);

  const response = await fetch(`${API_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      data.detail || "Nom d'utilisateur ou mot de passe incorrect."
    );
  }

  return data;
}

export async function apiFetch(endpoint, options = {}) {
  const token =
    typeof window !== "undefined"
      ? localStorage.getItem("access_token")
      : null;

  const headers = {
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (options.body && !(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(`${API_URL}${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");

    if (typeof window !== "undefined") {
      window.location.href = "/login";
    }

    throw new Error("Session expirée.");
  }

  const contentType = response.headers.get("content-type");

  if (contentType?.includes("application/json")) {
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.detail || "Erreur API");
    }

    return data;
  }

  if (!response.ok) {
    throw new Error("Erreur API");
  }

  return response;
}

export async function getDashboardSummary() {
  return apiFetch("/dashboard/summary");
}

export async function getAlerts() {
  return apiFetch("/alerte");
}

export async function getAlert(id) {
  return apiFetch(`/alerte/${id}`);
}

export async function getEvents() {
  return apiFetch("/evenement");
}

export async function getEvent(id) {
  return apiFetch(`/evenement/${id}`);
}

export async function createIncidentFromAlert(alertId) {
  return apiFetch(`/incident/from-alerte/${alertId}`, {
    method: "POST",
  });
}

export async function getIncident(id) {
  return apiFetch(`/incident/${id}`);
}

export async function updateIncident(id, data) {
  return apiFetch(`/incident/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function getIncidents() {
  return apiFetch("/incident");
}

export async function getUsers() {
  return apiFetch("/incident/users");
}

export async function getAlertsBySeverity() {
  return apiFetch("/dashboard/alerts-by-severity");
}

export async function getIncidentsByStatus() {
  return apiFetch("/dashboard/incidents-by-status");
}

export async function getAlertsOverTime(period = "24h") {
  return apiFetch(
    `/dashboard/alerts-over-time?period=${period}`
  );
}

export async function getIncidentsOverTime(period = "24h") {
  return apiFetch(
    `/dashboard/incidents-over-time?period=${period}`
  );
}

export async function getAlertsByCategory() {
  return apiFetch("/dashboard/alerts-by-category");
}

export async function getDashboardServices() {
  return apiFetch("/dashboard/services");
}

export async function getIOCs(page = 1, pageSize = 50) {
  return apiFetch(
    `/ioc?page=${page}&page_size=${pageSize}`
  );
}

export async function getIOC(id) {
  return apiFetch(`/ioc/${id}`);
}

/* ============================================================
   RESPONSE / ACTIONS
============================================================ */

export async function getResponseCatalog() {
  return apiFetch("/response/actions/catalog");
}

export async function getIncidentActions(incidentId) {
  return apiFetch(
    `/response/incidents/${incidentId}/actions`
  );
}

export async function createResponseAction(payload) {
  return apiFetch("/response/actions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

/* ============================================================
   COLLECT LOGS / TRIAGE
============================================================ */

export async function getCollectedLogs(incidentId) {
  return apiFetch(
    `/response/incidents/${incidentId}/collected-logs`
  );
}

export async function getGlpiStats() {
  return apiFetch("/dashboard/glpi-stats");
}

/* ============================================================
   ADMINISTRATION / RBAC
============================================================ */

export async function getAdminUsers() {
  return apiFetch("/admin/users");
}

export async function createAdminUser(data) {
  return apiFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function getAdminRoles() {
  return apiFetch("/admin/roles");
}

export async function getAdminPermissions() {
  return apiFetch("/admin/permissions");
}

export async function updateAdminUserStatus(userId, statut) {
  return apiFetch(
    `/admin/users/${userId}/status?statut=${encodeURIComponent(
      statut
    )}`,
    {
      method: "PATCH",
    }
  );
}

export async function assignAdminUserRole(userId, roleId) {
  return apiFetch(`/admin/users/${userId}/role/${roleId}`, {
    method: "PATCH",
  });
}

export async function getCurrentUser() {
  return apiFetch("/auth/me");
}
export function logout() {
  if (typeof window === "undefined") {
    return;
  }

  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");

  window.location.href = "/login";
}