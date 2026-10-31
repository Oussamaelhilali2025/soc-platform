"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();

    setError("");
    setLoading(true);

    try {
      const data = await login(username, password);

      if (data?.access_token) {
        localStorage.setItem("access_token", data.access_token);
      }

      if (data?.refresh_token) {
        localStorage.setItem("refresh_token", data.refresh_token);
      }

      window.location.href = "/dashboard";
    } catch (err) {
      console.error("Erreur de connexion :", err);
      setError("Identifiant ou mot de passe incorrect.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-slate-950 text-white">
      {/* VIDEO BACKGROUND */}
      <video
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        className="absolute inset-0 z-0 h-full w-full object-cover opacity-70"
      >
        <source src="/videos/security-background.mp4" type="video/mp4" />
      </video>

      {/* DARK OVERLAY */}
      <div className="absolute inset-0 z-10 bg-slate-950/55" />

      {/* GRID */}
      <div
        className="absolute inset-0 z-10 opacity-20"
        style={{
          backgroundImage:
            "linear-gradient(rgba(56,189,248,0.12) 1px, transparent 1px), linear-gradient(90deg, rgba(56,189,248,0.12) 1px, transparent 1px)",
          backgroundSize: "50px 50px",
        }}
      />

      {/* RADIAL VIGNETTE */}
      <div
        className="pointer-events-none absolute inset-0 z-10"
        style={{
          background:
            "radial-gradient(circle at center, transparent 0%, rgba(2,6,23,0.35) 45%, rgba(2,6,23,0.90) 100%)",
        }}
      />

      {/* GLOW ORBS */}
      <div
        className="absolute z-10 h-96 w-96 rounded-full bg-cyan-500/10 blur-3xl"
        style={{
          top: "-120px",
          left: "-120px",
          animation: "soc-drift-1 12s ease-in-out infinite",
        }}
      />
      <div
        className="absolute z-10 h-80 w-80 rounded-full bg-blue-500/10 blur-3xl"
        style={{
          right: "-100px",
          bottom: "-100px",
          animation: "soc-drift-2 15s ease-in-out infinite",
        }}
      />
      <div
        className="absolute z-10 h-64 w-64 rounded-full bg-violet-500/10 blur-3xl"
        style={{
          right: "25%",
          top: "15%",
          animation: "soc-drift-3 18s ease-in-out infinite",
        }}
      />

      {/* RADAR / SCAN LINE */}
      <div
        className="absolute left-0 right-0 z-10 h-px bg-cyan-400/20"
        style={{
          top: "50%",
          boxShadow: "0 0 25px rgba(34,211,238,0.25)",
          animation: "soc-scan 6s linear infinite",
        }}
      />

      {/* MAIN CONTENT */}
      <div className="relative z-20 flex min-h-screen items-center justify-center px-6 py-12">
        <div className="w-full max-w-md">
          {/* LOGO / HEADER */}
          <div className="mb-8 text-center">
            <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-2xl border border-cyan-400/30 bg-slate-950/70 shadow-[0_0_40px_rgba(34,211,238,0.15)] backdrop-blur-md">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-cyan-400/40 bg-cyan-400/10">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  className="h-6 w-6 text-cyan-400"
                  stroke="currentColor"
                  strokeWidth="1.5"
                >
                  <path d="M12 3L19 6V11C19 16 15.5 19.5 12 21C8.5 19.5 5 16 5 11V6L12 3Z" />
                  <path d="M9 12L11 14L15 10" />
                </svg>
              </div>
            </div>

            <h1 className="text-2xl font-semibold tracking-[0.25em] text-white">
              SOC PLATFORM
            </h1>
            <p className="mt-2 text-xs uppercase tracking-[0.2em] text-slate-500">
              Security Operations Center
            </p>
          </div>

          {/* LOGIN CARD */}
          <div className="relative overflow-hidden rounded-2xl border border-slate-700/60 bg-slate-950/75 shadow-2xl shadow-black/40 backdrop-blur-xl">
            {/* Top cyan line */}
            <div className="absolute left-0 right-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-400/70 to-transparent" />

            <div className="p-7 sm:p-8">
              <div className="mb-7">
                <p className="text-[10px] font-medium uppercase tracking-[0.2em] text-cyan-400">
                  Secure access
                </p>
                <h2 className="mt-2 text-xl font-semibold text-slate-100">
                  Connexion
                </h2>
                <p className="mt-2 text-sm text-slate-500">
                  Accédez à votre plateforme de supervision de sécurité.
                </p>
              </div>

              {/* ERROR */}
              {error && (
                <div className="mb-5 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3">
                  <p className="text-xs text-rose-400">{error}</p>
                </div>
              )}

              {/* FORM */}
              <form onSubmit={handleSubmit} className="space-y-5">
                {/* Username */}
                <div>
                  <label
                    htmlFor="username"
                    className="mb-2 block text-xs font-medium text-slate-400"
                  >
                    Nom d'utilisateur
                  </label>
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-900/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10"
                    placeholder="Entrez votre identifiant"
                  />
                </div>

                {/* Password */}
                <div>
                  <label
                    htmlFor="password"
                    className="mb-2 block text-xs font-medium text-slate-400"
                  >
                    Mot de passe
                  </label>
                  <input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                    className="w-full rounded-lg border border-slate-700 bg-slate-900/70 px-4 py-3 text-sm text-slate-100 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/10"
                    placeholder="Entrez votre mot de passe"
                  />
                </div>

                {/* Submit */}
                <button
                  type="submit"
                  disabled={loading}
                  className="group relative w-full overflow-hidden rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm font-medium text-cyan-300 transition hover:border-cyan-400/50 hover:bg-cyan-500/15 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <span className="relative z-10">
                    {loading ? "Connexion..." : "Se connecter"}
                  </span>
                  <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-cyan-400/10 to-transparent transition-transform duration-700 group-hover:translate-x-full" />
                </button>
              </form>

              {/* SECURITY INFO */}
              <div className="mt-7 border-t border-slate-800 pt-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)]" />
                    <span className="text-[10px] uppercase tracking-wider text-slate-500">
                      Système sécurisé
                    </span>
                  </div>
                  
                </div>
              </div>
            </div>
          </div>

          {/* FOOTER */}
          <p className="mt-6 text-center text-[10px] uppercase tracking-[0.15em] text-slate-600">
            SOC Platform · Security Monitoring & Incident Response
          </p>
        </div>
      </div>

      {/* ANIMATIONS */}
      <style jsx>{`
        @keyframes soc-drift-1 {
          0%,
          100% {
            transform: translate(0, 0) scale(1);
          }
          50% {
            transform: translate(80px, 50px) scale(1.15);
          }
        }

        @keyframes soc-drift-2 {
          0%,
          100% {
            transform: translate(0, 0) scale(1);
          }
          50% {
            transform: translate(-70px, -40px) scale(1.1);
          }
        }

        @keyframes soc-drift-3 {
          0%,
          100% {
            transform: translate(0, 0);
          }
          50% {
            transform: translate(-40px, 70px);
          }
        }

        @keyframes soc-scan {
          0% {
            transform: translateY(-45vh);
            opacity: 0;
          }
          10% {
            opacity: 1;
          }
          90% {
            opacity: 1;
          }
          100% {
            transform: translateY(45vh);
            opacity: 0;
          }
        }
      `}</style>
    </main>
  );
}