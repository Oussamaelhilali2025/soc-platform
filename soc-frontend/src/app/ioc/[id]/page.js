"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
ArrowLeft,
Copy,
Check,
RefreshCw,
Fingerprint,
Globe,
Hash,
Link as LinkIcon,
Mail,
FileText,
ShieldCheck,
Clock,
CalendarDays,
AlertCircle,
Activity,
Database,
Server,
AlertTriangle,
Crosshair,
Target,
ExternalLink,
Zap,
} from "lucide-react";

import AuthGuard from "@/components/auth/AuthGuard";
import { useRBAC } from "@/components/auth/RBACContext";
import { getIOC } from "@/lib/api";

const THEHIVE_URL =
  process.env.NEXT_PUBLIC_THEHIVE_URL || "http://localhost:9000";

function formatDate(dateString) {
if (!dateString) return "—";

const date = new Date(dateString);

if (Number.isNaN(date.getTime())) {
return dateString;
}

return date.toLocaleString("fr-FR", {
day: "2-digit",
month: "2-digit",
year: "numeric",
hour: "2-digit",
minute: "2-digit",
second: "2-digit",
});
}

function getTypeIcon(type) {
switch (type) {
case "IP":
return Globe;


case "DOMAIN":
  return Globe;

case "URL":
  return LinkIcon;

case "HASH_MD5":
case "HASH_SHA1":
case "HASH_SHA256":
  return Hash;

case "EMAIL":
  return Mail;

case "FILE":
  return FileText;

default:
  return Fingerprint;


}
}

function getTypeStyle(type) {
switch (type) {
case "IP":
return {
badge: "bg-blue-500/10 text-blue-400 border-blue-500/20",
icon: "text-blue-400",
};


case "DOMAIN":
  return {
    badge: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    icon: "text-purple-400",
  };

case "URL":
  return {
    badge: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    icon: "text-orange-400",
  };

case "HASH_MD5":
case "HASH_SHA1":
case "HASH_SHA256":
  return {
    badge: "bg-red-500/10 text-red-400 border-red-500/20",
    icon: "text-red-400",
  };

case "EMAIL":
  return {
    badge: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    icon: "text-cyan-400",
  };

case "FILE":
  return {
    badge: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    icon: "text-yellow-400",
  };

default:
  return {
    badge: "bg-gray-500/10 text-gray-400 border-gray-500/20",
    icon: "text-gray-400",
  };


}
}

function getRiskStyle(level) {
switch (String(level || "").toUpperCase()) {
case "CRITICAL":
return {
badge:
"bg-red-500/10 text-red-400 border-red-500/20",
text: "text-red-400",
};


case "HIGH":
  return {
    badge:
      "bg-orange-500/10 text-orange-400 border-orange-500/20",
    text: "text-orange-400",
  };

case "MEDIUM":
  return {
    badge:
      "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    text: "text-yellow-400",
  };

case "LOW":
  return {
    badge:
      "bg-green-500/10 text-green-400 border-green-500/20",
    text: "text-green-400",
  };

default:
  return {
    badge:
      "bg-gray-500/10 text-gray-400 border-gray-500/20",
    text: "text-gray-400",
  };


}
}

function getSeverityStyle(severity) {
switch (String(severity || "").toUpperCase()) {
case "CRITICAL":
return "bg-red-500/10 text-red-400 border-red-500/20";


case "HIGH":
  return "bg-orange-500/10 text-orange-400 border-orange-500/20";

case "MEDIUM":
  return "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";

case "LOW":
  return "bg-green-500/10 text-green-400 border-green-500/20";

default:
  return "bg-gray-500/10 text-gray-400 border-gray-500/20";


}
}

function getStatusStyle(status) {
switch (String(status || "").toUpperCase()) {
case "CLOSED":
case "RESOLVED":
return "bg-green-500/10 text-green-400 border-green-500/20";


case "IN_PROGRESS":
  return "bg-blue-500/10 text-blue-400 border-blue-500/20";

case "NEW":
case "OPEN":
  return "bg-orange-500/10 text-orange-400 border-orange-500/20";

default:
  return "bg-gray-500/10 text-gray-400 border-gray-500/20";


}
}

export default function IOCDetailPage() {
const params = useParams();
const router = useRouter();

const {
hasPermission,
loading: rbacLoading,
} = useRBAC();

const canReadIOC = hasPermission("IOC_READ");

const id = params?.id;

const [ioc, setIoc] = useState(null);
const [loading, setLoading] = useState(true);
const [refreshing, setRefreshing] = useState(false);
const [error, setError] = useState("");
const [copied, setCopied] = useState(false);

async function loadIOC(showRefresh = false) {
if (!id || !canReadIOC) {
return;
}


try {
  setError("");

  if (showRefresh) {
    setRefreshing(true);
  } else {
    setLoading(true);
  }

  const data = await getIOC(id);

  setIoc(data);
} catch (err) {
  console.error("Erreur lors du chargement de l'IOC :", err);

  setError(
    err?.message ||
      "Impossible de charger les informations de l'IOC."
  );
} finally {
  setLoading(false);
  setRefreshing(false);
}


}

useEffect(() => {
if (!rbacLoading && canReadIOC) {
loadIOC();
}
}, [id, canReadIOC, rbacLoading]);

async function copyIOC() {
if (!ioc?.valeur) return;


try {
  await navigator.clipboard.writeText(ioc.valeur);

  setCopied(true);

  setTimeout(() => {
    setCopied(false);
  }, 2000);
} catch (err) {
  console.error("Erreur copie :", err);
}


}

if (rbacLoading) {
return ( <AuthGuard> <div className="min-h-screen bg-[#0b1120] text-white flex items-center justify-center"> <div className="flex items-center gap-3 text-gray-400"> <RefreshCw className="w-5 h-5 animate-spin" />
Vérification des permissions... </div> </div> </AuthGuard>
);
}

if (!canReadIOC) {
return ( <AuthGuard> <div className="min-h-screen bg-[#0b1120] text-white"> <div className="max-w-6xl mx-auto px-6 py-8">
<button
onClick={() => router.back()}
className="flex items-center gap-2 text-gray-400 hover:text-white transition mb-8"
> <ArrowLeft className="w-4 h-4" />
Retour </button>


        <div className="bg-[#111827] border border-red-500/20 rounded-xl p-8">
          <div className="flex items-center gap-3 text-red-400 mb-3">
            <AlertCircle className="w-6 h-6" />

            <h1 className="text-lg font-semibold">
              Accès refusé
            </h1>
          </div>

          <p className="text-gray-400">
            Votre compte ne possède pas la permission nécessaire
            pour consulter cet IOC.
          </p>
        </div>
      </div>
    </div>
  </AuthGuard>
);


}

if (loading) {
return ( <AuthGuard> <div className="min-h-screen bg-[#0b1120] text-white flex items-center justify-center"> <div className="flex items-center gap-3 text-gray-400"> <RefreshCw className="w-5 h-5 animate-spin" />
Chargement de l'IOC... </div> </div> </AuthGuard>
);
}

if (error || !ioc) {
return ( <AuthGuard> <div className="min-h-screen bg-[#0b1120] text-white"> <div className="max-w-6xl mx-auto px-6 py-8">
<button
onClick={() => router.push("/ioc")}
className="flex items-center gap-2 text-gray-400 hover:text-white transition mb-8"
> <ArrowLeft className="w-4 h-4" />
Retour aux IOC </button>

        <div className="bg-[#111827] border border-red-500/20 rounded-xl p-8">
          <div className="flex items-center gap-3 text-red-400 mb-3">
            <AlertCircle className="w-6 h-6" />

            <h1 className="text-lg font-semibold">
              Impossible de charger l'IOC
            </h1>
          </div>

          <p className="text-gray-400">
            {error || "IOC introuvable."}
          </p>

          <button
            onClick={() => loadIOC()}
            className="mt-6 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 transition flex items-center gap-2"
          >
            <RefreshCw className="w-4 h-4" />
            Réessayer
          </button>
        </div>
      </div>
    </div>
  </AuthGuard>
);


}

const TypeIcon = getTypeIcon(ioc.type_ioc);
const typeStyle = getTypeStyle(ioc.type_ioc);

const isValidIOC = Number(ioc.is_ioc) === 1;

const virustotal = ioc.enrichment?.virustotal;
const abuseipdb = ioc.enrichment?.abuseipdb;

const isIP = ioc.type_ioc === "IP";

const securityContext = ioc.security_context;
const alerts = securityContext?.alerts || [];

return ( <AuthGuard> <div className="min-h-screen bg-[#0b1120] text-white">
{/* HEADER */} <header className="border-b border-gray-800 bg-[#0f172a]"> <div className="max-w-6xl mx-auto px-6 py-4"> <div className="flex items-center justify-between">
<button
onClick={() => router.push("/ioc")}
className="flex items-center gap-2 text-gray-400 hover:text-white transition"
> <ArrowLeft className="w-4 h-4" />
Retour aux IOC </button>


          <button
            onClick={() => loadIOC(true)}
            disabled={!canReadIOC || refreshing}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-700 bg-[#111827] hover:bg-gray-800 transition text-sm text-gray-300 disabled:opacity-50"
          >
            <RefreshCw
              className={`w-4 h-4 ${
                refreshing ? "animate-spin" : ""
              }`}
            />

            Actualiser
          </button>
        </div>
      </div>
    </header>

    {/* MAIN */}
    <main className="max-w-6xl mx-auto px-6 py-8">
      {/* TITLE */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <Fingerprint className="w-6 h-6 text-blue-400" />
          </div>

          <div>
            <h1 className="text-2xl font-semibold">
              Détail de l'IOC
            </h1>

            <p className="text-sm text-gray-500 mt-1">
              Informations et métadonnées de l'indicateur
            </p>
          </div>
        </div>
      </div>

      {/* IOC VALUE */}
      <section className="bg-[#111827] border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-start justify-between gap-6">
          <div className="flex-1 min-w-0">
            <p className="text-xs uppercase tracking-wider text-gray-500 mb-3">
              Valeur de l'indicateur
            </p>

            <div className="flex items-center gap-3">
              <p className="text-xl font-mono text-white break-all">
                {ioc.valeur || "—"}
              </p>

              <button
                onClick={copyIOC}
                title="Copier"
                className="flex-shrink-0 p-2 rounded-lg border border-gray-700 bg-gray-800 hover:bg-gray-700 transition"
              >
                {copied ? (
                  <Check className="w-4 h-4 text-green-400" />
                ) : (
                  <Copy className="w-4 h-4 text-gray-400" />
                )}
              </button>
            </div>

            {copied && (
              <p className="text-xs text-green-400 mt-2">
                IOC copié dans le presse-papiers.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* INFORMATION CARDS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {/* TYPE */}
        <section className="bg-[#111827] border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-5">
            <TypeIcon
              className={`w-5 h-5 ${typeStyle.icon}`}
            />

            <h2 className="text-sm font-medium text-gray-300">
              Type
            </h2>
          </div>

          <div>
            <span
              className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium ${typeStyle.badge}`}
            >
              <TypeIcon className="w-4 h-4" />
              {ioc.type_ioc || "NON CLASSÉ"}
            </span>
          </div>
        </section>

        {/* STATUS */}
        <section className="bg-[#111827] border border-gray-800 rounded-xl p-6">
          <div className="flex items-center gap-3 mb-5">
            <ShieldCheck
              className={`w-5 h-5 ${
                isValidIOC
                  ? "text-green-400"
                  : "text-gray-400"
              }`}
            />

            <h2 className="text-sm font-medium text-gray-300">
              Statut
            </h2>
          </div>

          <div>
            {isValidIOC ? (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-green-500/20 bg-green-500/10 text-green-400 text-sm font-medium">
                <Check className="w-4 h-4" />
                IOC valide
              </span>
            ) : (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-500/20 bg-gray-500/10 text-gray-400 text-sm font-medium">
                <AlertCircle className="w-4 h-4" />
                Non IOC
              </span>
            )}
          </div>
        </section>
      </div>

      {/* OBSERVATION DATES */}
      <section className="bg-[#111827] border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-6">
          <Clock className="w-5 h-5 text-blue-400" />

          <h2 className="text-base font-medium">
            Historique d'observation
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* FIRST */}
          <div className="border border-gray-800 rounded-lg p-5 bg-[#0f172a]">
            <div className="flex items-center gap-2 text-gray-500 text-xs uppercase tracking-wider mb-3">
              <CalendarDays className="w-4 h-4" />
              Première observation
            </div>

            <p className="text-gray-200 font-mono text-sm">
              {formatDate(ioc.date_premiere_observation)}
            </p>
          </div>

          {/* LAST */}
          <div className="border border-gray-800 rounded-lg p-5 bg-[#0f172a]">
            <div className="flex items-center gap-2 text-gray-500 text-xs uppercase tracking-wider mb-3">
              <CalendarDays className="w-4 h-4" />
              Dernière observation
            </div>

            <p className="text-gray-200 font-mono text-sm">
              {formatDate(ioc.date_derniere_observation)}
            </p>
          </div>
        </div>
      </section>

      {/* TECHNICAL INFORMATION */}
      <section className="bg-[#111827] border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-6">
          <Fingerprint className="w-5 h-5 text-purple-400" />

          <h2 className="text-base font-medium">
            Informations techniques
          </h2>
        </div>

        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 py-3 border-b border-gray-800">
            <span className="text-sm text-gray-500">
              Identifiant IOC
            </span>

            <span className="font-mono text-sm text-gray-300 break-all">
              {ioc.id_ioc}
            </span>
          </div>

          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 py-3 border-b border-gray-800">
            <span className="text-sm text-gray-500">
              Type
            </span>

            <span className="text-sm text-gray-300">
              {ioc.type_ioc || "NON CLASSÉ"}
            </span>
          </div>

          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 py-3">
            <span className="text-sm text-gray-500">
              Indicateur actif
            </span>

            <span className="text-sm text-gray-300">
              {isValidIOC ? "Oui" : "Non"}
            </span>
          </div>
        </div>
      </section>

      {/* THREAT INTELLIGENCE */}
      <section className="bg-[#111827] border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-2">
          <ShieldCheck className="w-5 h-5 text-cyan-400" />

          <h2 className="text-base font-medium">
            Threat Intelligence
          </h2>
        </div>

        <p className="text-sm text-gray-500 mb-6">
          Résultats d'enrichissement déjà collectés par la
          plateforme.
        </p>

        {/* VIRUSTOTAL */}
        <div className="border border-gray-800 rounded-xl bg-[#0f172a] p-5 mb-5">
          <div className="flex items-center justify-between gap-4 mb-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <Activity className="w-5 h-5 text-blue-400" />
              </div>

              <div>
                <h3 className="text-sm font-semibold text-gray-200">
                  VirusTotal
                </h3>

                <p className="text-xs text-gray-500 mt-1">
                  Analyse multi-moteurs
                </p>
              </div>
            </div>

            {virustotal ? (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-green-500/20 bg-green-500/10 text-green-400 text-xs font-medium">
                <Check className="w-3.5 h-3.5" />
                Résultat disponible
              </span>
            ) : (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-500/20 bg-gray-500/10 text-gray-400 text-xs font-medium">
                <AlertCircle className="w-3.5 h-3.5" />
                Aucun résultat
              </span>
            )}
          </div>

          {virustotal ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Malveillants
                  </p>

                  <p className="text-xl font-semibold text-red-400">
                    {virustotal.malicious_count ?? 0}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Suspects
                  </p>

                  <p className="text-xl font-semibold text-orange-400">
                    {virustotal.suspicious_count ?? 0}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Non détectés
                  </p>

                  <p className="text-xl font-semibold text-gray-300">
                    {virustotal.undetected_count ?? 0}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Moteurs analysés
                  </p>

                  <p className="text-xl font-semibold text-blue-400">
                    {virustotal.total_engines ?? 0}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Réputation
                  </p>

                  <p className="text-sm text-gray-300 font-mono">
                    {virustotal.reputation ?? "Non disponible"}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Dernière analyse
                  </p>

                  <p className="text-sm text-gray-300 font-mono">
                    {formatDate(
                      virustotal.last_analysis_date
                    )}
                  </p>
                </div>
              </div>

              {virustotal.permalink && (
                <div className="mt-4">
                  <a
                    href={virustotal.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm text-blue-400 hover:text-blue-300 transition inline-flex items-center gap-1"
                  >
                    Consulter le résultat VirusTotal
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              )}
            </>
          ) : (
            <div className="border border-gray-800 rounded-lg p-4">
              <p className="text-sm text-gray-500">
                Aucun résultat VirusTotal enregistré pour cet
                IOC.
              </p>
            </div>
          )}
        </div>

        {/* ABUSEIPDB */}
        <div className="border border-gray-800 rounded-xl bg-[#0f172a] p-5">
          <div className="flex items-center justify-between gap-4 mb-5">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
                <Database className="w-5 h-5 text-orange-400" />
              </div>

              <div>
                <h3 className="text-sm font-semibold text-gray-200">
                  AbuseIPDB
                </h3>

                <p className="text-xs text-gray-500 mt-1">
                  Réputation des adresses IP
                </p>
              </div>
            </div>

            {abuseipdb ? (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-green-500/20 bg-green-500/10 text-green-400 text-xs font-medium">
                <Check className="w-3.5 h-3.5" />
                Résultat disponible
              </span>
            ) : isIP ? (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-500/20 bg-gray-500/10 text-gray-400 text-xs font-medium">
                <AlertCircle className="w-3.5 h-3.5" />
                Aucun résultat
              </span>
            ) : (
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-gray-500/20 bg-gray-500/10 text-gray-400 text-xs font-medium">
                Non applicable
              </span>
            )}
          </div>

          {abuseipdb ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Score de confiance
                  </p>

                  <p className="text-xl font-semibold text-red-400">
                    {abuseipdb.abuse_confidence_score ?? 0}%
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Signalements
                  </p>

                  <p className="text-xl font-semibold text-orange-400">
                    {abuseipdb.total_reports ?? 0}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Utilisateurs distincts
                  </p>

                  <p className="text-xl font-semibold text-gray-300">
                    {abuseipdb.num_distinct_users ?? 0}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Tor
                  </p>

                  <p className="text-xl font-semibold text-purple-400">
                    {abuseipdb.is_tor ? "Oui" : "Non"}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Pays
                  </p>

                  <p className="text-sm text-gray-300">
                    {abuseipdb.country_name ||
                      abuseipdb.country_code ||
                      "Non disponible"}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Fournisseur / ISP
                  </p>

                  <p className="text-sm text-gray-300">
                    {abuseipdb.isp || "Non disponible"}
                  </p>
                </div>

                <div className="border border-gray-800 rounded-lg p-4">
                  <p className="text-xs text-gray-500 mb-2">
                    Type d'utilisation
                  </p>

                  <p className="text-sm text-gray-300">
                    {abuseipdb.usage_type || "Non disponible"}
                  </p>
                </div>
              </div>

              <div className="mt-4 border border-gray-800 rounded-lg p-4">
                <p className="text-xs text-gray-500 mb-2">
                  Dernier signalement
                </p>

                <p className="text-sm text-gray-300 font-mono">
                  {formatDate(abuseipdb.last_reported_at)}
                </p>
              </div>
            </>
          ) : (
            <div className="border border-gray-800 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <Server className="w-4 h-4 text-gray-500 mt-0.5" />

                <div>
                  <p className="text-sm text-gray-400">
                    {isIP
                      ? "Aucun résultat AbuseIPDB enregistré pour cette adresse IP."
                      : "AbuseIPDB est principalement destiné à l'analyse de réputation des adresses IP."}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* SECURITY CONTEXT */}
      <section className="bg-[#111827] border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center gap-3 mb-2">
          <ShieldCheck className="w-5 h-5 text-purple-400" />

          <h2 className="text-base font-medium">
            Contexte de sécurité
          </h2>
        </div>

        <p className="text-sm text-gray-500 mb-6">
          Événements et alertes de sécurité associés à cet
          indicateur.
        </p>

        {alerts.length === 0 ? (
          <div className="border border-gray-800 rounded-lg p-5 bg-[#0f172a]">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-gray-500" />

              <p className="text-sm text-gray-400">
                Aucun événement de sécurité associé à cet IOC.
              </p>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {alerts.map((alert, index) => {
              const event = alert.event || {};
              const risk = alert.risk || {};
              const mitre = alert.mitre || {};
              const riskStyle = getRiskStyle(risk.niveau);
              const incident = alert.incident;

              const techniques = Array.isArray(mitre.technique)
                ? mitre.technique
                : mitre.technique
                ? [mitre.technique]
                : [];

              const tactics = Array.isArray(mitre.tactic)
                ? mitre.tactic
                : mitre.tactic
                ? [mitre.tactic]
                : [];

              const techniqueIds = Array.isArray(mitre.id)
                ? mitre.id
                : mitre.id
                ? [mitre.id]
                : [];

              return (
                <div
                  key={
                    alert.id_alerte ||
                    alert.identifiant_externe ||
                    index
                  }
                  className="border border-gray-800 rounded-xl bg-[#0f172a] overflow-hidden"
                >
                  {/* ALERT HEADER */}
                  <div className="p-5 border-b border-gray-800">
                    <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-lg bg-orange-500/10 border border-orange-500/20">
                          <AlertTriangle className="w-5 h-5 text-orange-400" />
                        </div>

                        <div>
                          <p className="text-xs uppercase tracking-wider text-gray-500 mb-1">
                            Alerte de sécurité
                          </p>

                          <h3 className="text-base font-semibold text-gray-200">
                            {alert.titre || "Alerte sans titre"}
                          </h3>

                          <p className="text-xs text-gray-500 mt-2 font-mono break-all">
                            {alert.identifiant_externe || "—"}
                          </p>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-xs font-medium ${getSeverityStyle(
                            alert.severite
                          )}`}
                        >
                          {alert.severite || "—"}
                        </span>

                        <span
                          className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-xs font-medium ${getStatusStyle(
                            alert.statut
                          )}`}
                        >
                          {alert.statut || "—"}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* EVENT */}
                  <div className="p-5 border-b border-gray-800">
                    <div className="flex items-center gap-2 mb-4">
                      <Activity className="w-4 h-4 text-blue-400" />

                      <h3 className="text-sm font-semibold text-gray-300">
                        Événement source
                      </h3>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Règle Wazuh
                        </p>

                        <p className="text-sm font-mono text-gray-200">
                          {event.rule_id || "—"}
                        </p>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Niveau Wazuh
                        </p>

                        <p className="text-xl font-semibold text-orange-400">
                          {event.niveau_wazuh ?? "—"}
                        </p>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Machine
                        </p>

                        <p className="text-sm text-gray-200 break-all">
                          {event.hostname || "—"}
                        </p>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Type
                        </p>

                        <p className="text-sm text-gray-200">
                          {event.type_evenement || "—"}
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          ID événement
                        </p>

                        <p className="text-xs font-mono text-gray-300 break-all">
                          {event.id_evenement || "—"}
                        </p>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Date de l'événement
                        </p>

                        <p className="text-sm font-mono text-gray-300">
                          {formatDate(event.timestamp)}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* RISK */}
                  <div className="p-5 border-b border-gray-800">
                    <div className="flex items-center gap-2 mb-4">
                      <Zap className="w-4 h-4 text-yellow-400" />

                      <h3 className="text-sm font-semibold text-gray-300">
                        Évaluation du risque
                      </h3>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Score de risque
                        </p>

                        <p
                          className={`text-3xl font-bold ${riskStyle.text}`}
                        >
                          {risk.score ?? "—"}
                        </p>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Niveau
                        </p>

                        <span
                          className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-sm font-medium ${riskStyle.badge}`}
                        >
                          {risk.niveau || "NON ÉVALUÉ"}
                        </span>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Action recommandée
                        </p>

                        <p className="text-sm font-semibold text-gray-200">
                          {risk.action || "—"}
                        </p>
                      </div>
                    </div>

                    {risk.raison && (
                      <div className="mt-4 border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Justification
                        </p>

                        <p className="text-sm text-gray-300 leading-relaxed">
                          {risk.raison}
                        </p>
                      </div>
                    )}

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Création de case
                        </p>

                        <span
                          className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-medium ${
                            risk.force_case
                              ? "bg-red-500/10 text-red-400 border-red-500/20"
                              : "bg-gray-500/10 text-gray-400 border-gray-500/20"
                          }`}
                        >
                          {risk.force_case ? (
                            <>
                              <Check className="w-3.5 h-3.5" />
                              Case forcée
                            </>
                          ) : (
                            "Non forcée"
                          )}
                        </span>
                      </div>

                      <div className="border border-gray-800 rounded-lg p-4">
                        <p className="text-xs text-gray-500 mb-2">
                          Calcul du risque
                        </p>

                        <p className="text-sm font-mono text-gray-300">
                          {formatDate(risk.date_calcul)}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* MITRE */}
                  {(techniques.length > 0 ||
                    tactics.length > 0 ||
                    techniqueIds.length > 0) && (
                    <div className="p-5 border-b border-gray-800">
                      <div className="flex items-center gap-2 mb-4">
                        <Crosshair className="w-4 h-4 text-red-400" />

                        <h3 className="text-sm font-semibold text-gray-300">
                          MITRE ATT&CK
                        </h3>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {techniqueIds.length > 0 && (
                          <div className="border border-gray-800 rounded-lg p-4">
                            <p className="text-xs text-gray-500 mb-3">
                              Identifiant technique
                            </p>

                            <div className="flex flex-wrap gap-2">
                              {techniqueIds.map((item, i) => (
                                <span
                                  key={`${item}-${i}`}
                                  className="inline-flex items-center px-3 py-1.5 rounded-lg bg-red-500/10 text-red-400 border border-red-500/20 text-xs font-mono"
                                >
                                  {item}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {techniques.length > 0 && (
                          <div className="border border-gray-800 rounded-lg p-4">
                            <p className="text-xs text-gray-500 mb-3">
                              Technique
                            </p>

                            <div className="flex flex-wrap gap-2">
                              {techniques.map((item, i) => (
                                <span
                                  key={`${item}-${i}`}
                                  className="inline-flex items-center px-3 py-1.5 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20 text-xs"
                                >
                                  {item}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}

                        {tactics.length > 0 && (
                          <div className="border border-gray-800 rounded-lg p-4 md:col-span-2">
                            <p className="text-xs text-gray-500 mb-3">
                              Tactiques
                            </p>

                            <div className="flex flex-wrap gap-2">
                              {tactics.map((item, i) => (
                                <span
                                  key={`${item}-${i}`}
                                  className="inline-flex items-center px-3 py-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 text-xs"
                                >
                                  {item}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* INCIDENT / THEHIVE */}
                  {incident && (
                    <div className="p-5">
                      <div className="flex items-center gap-2 mb-4">
                        <Target className="w-4 h-4 text-cyan-400" />

                        <h3 className="text-sm font-semibold text-gray-300">
                          Incident / TheHive
                        </h3>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div className="border border-gray-800 rounded-lg p-4">
                          <p className="text-xs text-gray-500 mb-2">
                            Statut
                          </p>

                          <span
                            className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-xs font-medium ${getStatusStyle(
                              incident.statut
                            )}`}
                          >
                            {incident.statut || "—"}
                          </span>
                        </div>

                        <div className="border border-gray-800 rounded-lg p-4">
                          <p className="text-xs text-gray-500 mb-2">
                            Priorité
                          </p>

                          <span
                            className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-xs font-medium ${getSeverityStyle(
                              incident.priorite
                            )}`}
                          >
                            {incident.priorite || "—"}
                          </span>
                        </div>

                        <div className="border border-gray-800 rounded-lg p-4">
                          <p className="text-xs text-gray-500 mb-2">
                            Sévérité
                          </p>

                          <span
                            className={`inline-flex items-center px-3 py-1.5 rounded-lg border text-xs font-medium ${getSeverityStyle(
                              incident.severite
                            )}`}
                          >
                            {incident.severite || "—"}
                          </span>
                        </div>

                        <div className="border border-gray-800 rounded-lg p-4">
                          <p className="text-xs text-gray-500 mb-2">
                            ID incident
                          </p>

                          <p className="text-xs font-mono text-gray-300 break-all">
                            {incident.id_incident || "—"}
                          </p>
                        </div>
                      </div>

                      {incident.identifiant_thehive && (
                        <div className="mt-4 border border-gray-800 rounded-lg p-4">
                          <div className="flex items-center justify-between gap-4">
                            <div>
                              <p className="text-xs text-gray-500 mb-2">
                                Identifiant TheHive
                              </p>

                              <p className="text-sm font-mono text-cyan-400 break-all">
                                {incident.identifiant_thehive}
                              </p>
                            </div>

                            <a
                              href={THEHIVE_URL}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex-shrink-0 inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-700 bg-gray-800 hover:bg-gray-700 transition text-xs text-gray-300"
                            >
                              Ouvrir TheHive
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* ALERT METADATA */}
                  <div className="px-5 py-4 bg-[#0b1120] border-t border-gray-800">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-xs text-gray-500 mb-1">
                          Création de l'alerte
                        </p>

                        <p className="text-xs font-mono text-gray-400">
                          {formatDate(alert.date_creation)}
                        </p>
                      </div>

                      <div>
                        <p className="text-xs text-gray-500 mb-1">
                          Mise à jour
                        </p>

                        <p className="text-xs font-mono text-gray-400">
                          {formatDate(alert.date_mise_a_jour)}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>
    </main>
  </div>
</AuthGuard>


);
}
