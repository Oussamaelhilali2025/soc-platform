"use client";

import { createContext, useContext, useEffect, useState } from "react";

import { getCurrentUser } from "@/lib/api";

const RBACContext = createContext(null);

export function RBACProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const loadUser = async () => {
    
    try {
    setLoading(true);

    const token = localStorage.getItem("access_token");

    console.log("RBAC TOKEN AVANT /auth/me :", token);

    const data = await getCurrentUser();

    console.log("RBAC /auth/me :", data);

    setUser(data);
  } catch (error) {
    console.error("Erreur chargement utilisateur RBAC :", error);
    setUser(null);
  } finally {
    setLoading(false);
  }
  };

  useEffect(() => {
  if (typeof window === "undefined") {
    return;
  }

  const token = localStorage.getItem("access_token");

  console.log("RBAC TOKEN AU DEMARRAGE :", token);

  if (token) {
    loadUser();
  } else {
    console.log("RBAC : aucun access_token trouvé");
    setLoading(false);
  }
}, []);

  const permissions = Array.isArray(user?.permissions)
    ? user.permissions.map((permission) =>
        typeof permission === "string"
          ? permission
          : permission?.code
      ).filter(Boolean)
    : [];

  const roles = Array.isArray(user?.roles)
    ? user.roles.map((role) =>
        typeof role === "string"
          ? role
          : role?.nom || role?.name
      ).filter(Boolean)
    : [];

  const hasPermission = (permission) => {
    if (!permission) {
      return false;
    }

    return permissions.includes(permission);
  };

  const hasAnyPermission = (requiredPermissions) => {
    if (!Array.isArray(requiredPermissions)) {
      return false;
    }

    return requiredPermissions.some((permission) =>
      permissions.includes(permission)
    );
  };

  const hasAllPermissions = (requiredPermissions) => {
    if (!Array.isArray(requiredPermissions)) {
      return false;
    }

    return requiredPermissions.every((permission) =>
      permissions.includes(permission)
    );
  };

  const hasRole = (role) => {
    if (!role) {
      return false;
    }

    return roles.includes(role);
  };
  console.log("RBAC STATE :", {
  user,
  loading,
  roles,
  permissions,
  token: typeof window !== "undefined"
    ? localStorage.getItem("access_token")
    : null,
});

  return (
    <RBACContext.Provider
      value={{
        user,
        roles,
        permissions,
        loading,
        hasPermission,
        hasAnyPermission,
        hasAllPermissions,
        hasRole,
        reloadUser: loadUser,
      }}
    >
      {children}
    </RBACContext.Provider>
  );
}

export function useRBAC() {
  const context = useContext(RBACContext);

  if (!context) {
    throw new Error(
      "useRBAC doit être utilisé à l'intérieur de RBACProvider"
    );
  }


  return context;
}