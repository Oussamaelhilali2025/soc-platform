"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  getAlert,
  getEvents,
  createIncidentFromAlert,
} from "@/lib/api";
import { useRBAC } from "@/components/auth/RBACContext";

const THEHIVE_URL =
  process.env.NEXT_PUBLIC_THEHIVE_URL || "http://localhost:9000";

/* ============================================================
   GENERAL HELPERS
   ============================================================ */

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
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

function isMeaningfulValue(value) {
  if (value === null || value === undefined) {
    return false;
  }

  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }

  const normalized = String(value)
    .trim()
    .toLowerCase();

  return (
    normalized !== "" &&
    normalized !== "n/a" &&
    normalized !== "na" &&
    normalized !== "null" &&
    normalized !== "none" &&
    normalized !== "undefined" &&
    normalized !== "—" &&
    normalized !== "-"
  );
}

function normalizeText(value) {
  return String(value ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/&/g, " et ")
    .replace(/['’`]/g, " ")
    .replace(/[^a-zA-Z0-9]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function cleanMarkdown(value) {
  return String(value ?? "")
    .replace(/\r/g, "")
    .replace(/\\n/g, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<p[^>]*>/gi, "")
    .replace(/\s*#{1,6}\s*/g, " ")
    .replace(/\*\*/g, "")
    .replace(/__/g, "")
    .replace(/`/g, "")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function safeJsonObject(value) {
  if (!value) {
    return {};
  }

  if (
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return value;
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);

      if (
        parsed &&
        typeof parsed === "object" &&
        !Array.isArray(parsed)
      ) {
        return parsed;
      }
    } catch {
      return {};
    }
  }

  return {};
}

function safeJsonValue(value) {
  if (typeof value !== "string") {
    return value;
  }

  const trimmed = value.trim();

  if (!trimmed) {
    return value;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function getValue(object, ...keys) {
  const source = safeJsonObject(object);

  for (const key of keys) {
    if (
      source[key] !== undefined &&
      source[key] !== null &&
      isMeaningfulValue(source[key])
    ) {
      return source[key];
    }
  }

  return null;
}

function getFlexibleValue(object, ...keys) {
  const source = safeJsonObject(object);

  const direct = getValue(source, ...keys);

  if (isMeaningfulValue(direct)) {
    return direct;
  }

  const normalizedKeys = keys.map(normalizeText);

  for (const [key, value] of Object.entries(source)) {
    if (
      normalizedKeys.includes(normalizeText(key)) &&
      isMeaningfulValue(value)
    ) {
      return value;
    }
  }

  return null;
}

function normalizeExternalId(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).trim();
}

/* ============================================================
   SOC DESCRIPTION PARSER
   ============================================================ */

function normalizeDescriptionForParser(description) {
  return String(description ?? "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n")
    .replace(/\\r\\n/g, "\n")
    .replace(/\\n/g, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<p[^>]*>/gi, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseSocSummary(description) {
  const text =
    normalizeDescriptionForParser(description);

  const result = {
    summary: "",
    sections: {},
  };

  if (!text) {
    return result;
  }

  const summaryPatterns = [
    /(?:^|\n)\s*\*{0,2}résumé\s*:\s*\*{0,2}\s*([\s\S]*?)(?=\n\s*#{1,6}\s+|\n\s*\*{0,2}[A-Za-zÀ-ÿ][^:\n]{0,80}\s*:\s*\*{0,2}|$)/i,

    /(?:^|\n)\s*\*{0,2}summary\s*:\s*\*{0,2}\s*([\s\S]*?)(?=\n\s*#{1,6}\s+|\n\s*\*{0,2}[A-Za-zÀ-ÿ][^:\n]{0,80}\s*:\s*\*{0,2}|$)/i,
  ];

  for (const pattern of summaryPatterns) {
    const match = text.match(pattern);

    if (match?.[1]) {
      const cleaned = cleanMarkdown(match[1]);

      if (isMeaningfulValue(cleaned)) {
        result.summary = cleaned;
        break;
      }
    }
  }

  const headingRegex =
    /(?:^|\n)\s*#{1,6}\s*([^\n]+)\n?([\s\S]*?)(?=(?:\n|^)#{1,6}\s+|$)/g;

  let match;

  while ((match = headingRegex.exec(text)) !== null) {
    const rawTitle = match[1] || "";
    const body = match[2] || "";

    const title = cleanMarkdown(rawTitle)
      .replace(/:$/, "")
      .trim();

    if (!title) {
      continue;
    }

    result.sections[title] = body.trim();
  }

  if (
    Object.keys(result.sections).length === 0 &&
    !result.summary
  ) {
    result.summary = cleanMarkdown(text);
  }

  return result;
}

function getSection(sections, ...names) {
  const source = sections || {};

  const targets = names
    .flat()
    .filter(Boolean)
    .map(normalizeText);

  for (const [key, value] of Object.entries(source)) {
    const normalizedKey = normalizeText(key);

    if (
      targets.some(
        (target) =>
          normalizedKey === target ||
          normalizedKey.includes(target) ||
          target.includes(normalizedKey)
      )
    ) {
      return value || "";
    }
  }

  return "";
}

/* ============================================================
   LABELED FIELDS PARSER
   ============================================================ */

function parseLabeledFields(text) {
  const result = {};

  if (!text) {
    return result;
  }

  const normalized = normalizeDescriptionForParser(text);

  const lines = normalized
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);

  for (const rawLine of lines) {
    const line = rawLine
      .replace(/^[-*•]\s*/, "")
      .trim();

    const parts = line
      .split("|")
      .map((item) => item.trim())
      .filter(Boolean);

    for (const partRaw of parts) {
      const part = partRaw
        .replace(/^[-*•]\s*/, "")
        .trim();

      let match = part.match(
        /^\*{0,2}\s*(.+?)\s*\*{0,2}\s*:\s*\*{0,2}\s*(.*?)\s*\*{0,2}\s*$/i
      );

      if (!match) {
        match = part.match(
          /^\*{0,2}\s*(.+?)\s*\*{0,2}\s*=\s*(.*?)\s*$/i
        );
      }

      if (match) {
        const key = cleanMarkdown(match[1])
          .replace(/:$/, "")
          .trim();

        const value = cleanMarkdown(match[2]);

        if (
          key &&
          isMeaningfulValue(value)
        ) {
          result[key] = value;
        }
      }
    }
  }

  return result;
}

function getSummaryField(fields, ...names) {
  const source = fields || {};

  const normalizedTargets = names
    .filter(Boolean)
    .map(normalizeText);

  for (const [key, value] of Object.entries(source)) {
    if (
      normalizedTargets.includes(
        normalizeText(key)
      ) &&
      isMeaningfulValue(value)
    ) {
      return value;
    }
  }

  for (const [key, value] of Object.entries(source)) {
    const normalizedKey =
      normalizeText(key);

    if (
      normalizedTargets.some(
        (target) =>
          normalizedKey.includes(target) ||
          target.includes(normalizedKey)
      ) &&
      isMeaningfulValue(value)
    ) {
      return value;
    }
  }

  return null;
}

/* ============================================================
   NESTED DATA HELPERS
   ============================================================ */

function findNestedValue(object, paths) {
  for (const path of paths) {
    let current = object;

    for (const key of path) {
      if (
        current === null ||
        current === undefined ||
        typeof current !== "object"
      ) {
        current = null;
        break;
      }

      current = current[key];
    }

    if (isMeaningfulValue(current)) {
      return current;
    }
  }

  return null;
}

function findNestedValueInObjects(objects, paths) {
  for (const object of objects) {
    if (!object) {
      continue;
    }

    const value =
      findNestedValue(object, paths);

    if (isMeaningfulValue(value)) {
      return value;
    }
  }

  return null;
}

function getFirstObject(...values) {
  for (const value of values) {
    const parsed = safeJsonValue(value);

    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      Object.keys(parsed).length > 0
    ) {
      return parsed;
    }
  }

  return {};
}

function unwrapObject(value) {
  const parsed = safeJsonValue(value);

  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed)
  ) {
    return {};
  }

  const candidates = [
    parsed,

    parsed.data,
    parsed.result,
    parsed.message,
    parsed.payload,

    parsed.data?.classification,
    parsed.result?.classification,
    parsed.message?.classification,

    parsed.data?.normalized_data,
    parsed.result?.normalized_data,
    parsed.message?.normalized_data,

    parsed.data?.donnees_normalisees,
    parsed.result?.donnees_normalisees,
    parsed.message?.donnees_normalisees,
  ];

  return getFirstObject(...candidates);
}

/* ============================================================
   ARRAYS
   ============================================================ */

function normalizeStringArray(value) {
  const parsed = safeJsonValue(value);

  if (Array.isArray(parsed)) {
    return parsed
      .filter(isMeaningfulValue)
      .map((item) => {
        if (
          typeof item === "object"
        ) {
          return (
            item.name ||
            item.id ||
            item.value ||
            item.technique ||
            item.tactic ||
            JSON.stringify(item)
          );
        }

        return String(item).trim();
      })
      .filter(isMeaningfulValue);
  }

  if (isMeaningfulValue(parsed)) {
    return [String(parsed).trim()];
  }

  return [];
}

function normalizeRiskLevel(value) {
  const normalized = String(value ?? "")
    .trim()
    .toUpperCase();

  if (
    normalized === "LOW" ||
    normalized === "MEDIUM" ||
    normalized === "HIGH" ||
    normalized === "CRITICAL"
  ) {
    return normalized;
  }

  return null;
}

/* ============================================================
   IOC NORMALISATION
   ============================================================ */

function normalizeIocList(value) {
  if (!value) {
    return [];
  }

  const parsed = safeJsonValue(value);

  if (Array.isArray(parsed)) {
    return parsed;
  }

  if (
    parsed &&
    typeof parsed === "object"
  ) {
    if (Array.isArray(parsed.items)) {
      return parsed.items;
    }

    if (Array.isArray(parsed.results)) {
      return parsed.results;
    }

    if (Array.isArray(parsed.iocs)) {
      return parsed.iocs;
    }

    return [parsed];
  }

  return [];
}

/* ============================================================
   THREAT INTELLIGENCE
   ============================================================ */

function normalizeTiList(value) {
  if (!value) {
    return [];
  }

  const parsed = safeJsonValue(value);

  if (Array.isArray(parsed)) {
    return parsed.filter(
      (item) =>
        item &&
        typeof item === "object"
    );
  }

  if (
    parsed &&
    typeof parsed === "object"
  ) {
    if (Array.isArray(parsed.items)) {
      return normalizeTiList(
        parsed.items
      );
    }

    if (Array.isArray(parsed.results)) {
      return normalizeTiList(
        parsed.results
      );
    }

    if (Array.isArray(parsed.data)) {
      return normalizeTiList(
        parsed.data
      );
    }

    return [parsed];
  }

  return [];
}

function normalizeThreatIntelligence(value) {
  if (!value) {
    return {
      virustotal: [],
      abuseipdb: [],
    };
  }

  const parsed = safeJsonValue(value);

  if (Array.isArray(parsed)) {
    const virustotal =
      parsed.filter((item) => {
        const type = String(
          item?.source ||
            item?.provider ||
            item?.type_ti ||
            ""
        ).toLowerCase();

        return (
          type.includes("virus") ||
          type === "vt" ||
          item?.id_ti_vt !== undefined
        );
      });

    const abuseipdb =
      parsed.filter((item) => {
        const type = String(
          item?.source ||
            item?.provider ||
            item?.type_ti ||
            ""
        ).toLowerCase();

        return (
          type.includes("abuse") ||
          item?.id_ti_abuse !== undefined
        );
      });

    return {
      virustotal,
      abuseipdb,
    };
  }

  const object =
    safeJsonObject(parsed);

  return {
    virustotal: normalizeTiList(
      object.virustotal ??
        object.virusTotal ??
        object.virustotal_results ??
        object.vt ??
        object.virus_total
    ),

    abuseipdb: normalizeTiList(
      object.abuseipdb ??
        object.abuseIPDB ??
        object.abuseipdb_results ??
        object.abuse ??
        object.abuse_ipdb
    ),
  };
}

/* ============================================================
   EVENT HELPERS
   ============================================================ */

function extractEvents(data) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.items)) {
    return data.items;
  }

  if (Array.isArray(data?.events)) {
    return data.events;
  }

  if (Array.isArray(data?.evenements)) {
    return data.evenements;
  }

  if (Array.isArray(data?.data)) {
    return data.data;
  }

  if (Array.isArray(data?.results)) {
    return data.results;
  }

  return [];
}

function getEventExternalId(event) {
  return (
    getValue(
      event,
      "identifiant_externe",
      "external_id",
      "externalId",
      "event_id",
      "id_event"
    ) || ""
  );
}

function getEventPayload(event) {
  if (!event) {
    return {};
  }

  const direct =
    getValue(
      event,
      "donnees_brutes",
      "data",
      "payload",
      "raw_data",
      "rawData"
    );

  if (direct) {
    return safeJsonValue(direct) || {};
  }

  return {};
}

/* ============================================================
   SOLUTIONS
   ============================================================ */

function extractSolutionLines(section) {
  if (!section) {
    return [];
  }

  return String(section)
    .split("\n")
    .map((line) =>
      cleanMarkdown(line)
    )
    .map((line) =>
      line.replace(/^[-*•]\s*/, "").trim()
    )
    .filter(Boolean);
}

/* ============================================================
   UI COMPONENTS
   ============================================================ */

function InfoItem({ label, value }) {
  const filled =
    isMeaningfulValue(value);

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3.5 py-3">
      <div className="mb-1.5 text-[11px] font-medium tracking-wide opacity-55">
        {label}
      </div>

      <div
        className={`break-words text-sm ${
          filled
            ? "font-medium"
            : "opacity-40"
        }`}
      >
        {filled
          ? String(value)
          : "—"}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6">
      <div className="mb-4 flex items-center gap-2.5 border-b border-[var(--border)] pb-3">
        <span className="h-3.5 w-[3px] rounded-full bg-[var(--accent)]" />

        <h2 className="text-[13px] font-semibold tracking-wide">
          {title}
        </h2>
      </div>

      {children}
    </section>
  );
}

function TimelineItem({
  title,
  date,
  description,
  active = false,
}) {
  return (
    <div className="relative flex gap-4">
      <div className="flex flex-col items-center">
        <div
          className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${
            active
              ? "bg-[var(--accent)] ring-4 ring-[var(--accent)]/15"
              : "bg-[var(--border)]"
          }`}
        />

        <div className="mt-1 min-h-10 w-px flex-1 bg-[var(--border)]" />
      </div>

      <div className="pb-5">
        <div className="text-sm font-semibold">
          {title}
        </div>

        {date && (
          <div className="mt-1 text-xs opacity-55">
            {formatDate(date)}
          </div>
        )}

        {description && (
          <div className="mt-1.5 text-sm opacity-75">
            {description}
          </div>
        )}
      </div>
    </div>
  );
}

function InvestigationStep({
  title,
  status,
  children,
  available = false,
}) {
  return (
    <div
      className={`rounded-lg border p-4 ${
        available
          ? "border-[var(--accent)]/30"
          : "border-[var(--border)]"
      }`}
    >
      <div className="flex items-center justify-between gap-4">
        <div className="text-sm font-semibold">
          {title}
        </div>

        <span
          className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${
            available
              ? "border-[var(--accent)] text-[var(--accent)]"
              : "border-[var(--border)] opacity-55"
          }`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              available
                ? "bg-[var(--accent)]"
                : "bg-current opacity-60"
            }`}
          />

          {status}
        </span>
      </div>

      {children && (
        <div className="mt-3.5 border-t border-[var(--border)] pt-3.5">
          {children}
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const value = String(
    severity || "UNKNOWN"
  ).toUpperCase();

  let className =
    "border-[var(--border)] opacity-70";

  const dot = "bg-current";

  if (
    value === "CRITICAL" ||
    value === "HIGH"
  ) {
    className =
      "border-[var(--critical)] text-[var(--critical)] bg-[var(--critical)]/5";
  } else if (value === "MEDIUM") {
    className =
      "border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/5";
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${className}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${dot}`}
      />

      {value}
    </span>
  );
}

function StatusBadge({ status }) {
  const value = String(
    status || "UNKNOWN"
  ).toUpperCase();

  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] px-3 py-1 text-xs font-semibold opacity-80">
      <span className="h-1.5 w-1.5 rounded-full bg-current opacity-70" />

      {value}
    </span>
  );
}

/* ============================================================
   VIRUSTOTAL
   ============================================================ */

function VirusTotalCard({ item }) {
  const type =
    item?.type_ioc ||
    item?.type ||
    "IOC";

  const value =
    item?.valeur ??
    item?.value ??
    item?.ioc ??
    item?.url ??
    item?.domain ??
    item?.hash;

  const malicious =
    item?.malicious_count ??
    item?.malicious ??
    0;

  const suspicious =
    item?.suspicious_count ??
    item?.suspicious ??
    0;

  const harmless =
    item?.harmless_count ??
    item?.harmless ??
    0;

  const undetected =
    item?.undetected_count ??
    item?.undetected ??
    0;

  const total =
    item?.total_engines ??
    item?.total ??
    Number(malicious) +
      Number(suspicious) +
      Number(harmless) +
      Number(undetected);

  const reputation =
    item?.reputation;

  const lastAnalysisDate =
    item?.last_analysis_date ??
    item?.lastAnalysisDate;

  const permalink =
    item?.permalink ??
    item?.virustotal_url ??
    item?.url_vt;

  return (
    <div className="rounded-lg border border-[var(--border)] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-semibold uppercase tracking-wide opacity-60">
          {type}
        </div>

        <span className="rounded-full border border-[var(--border)] px-2 py-1 text-xs">
          {total} moteurs
        </span>
      </div>

      <div className="mb-4 break-all text-sm font-medium">
        {isMeaningfulValue(value)
          ? value
          : "—"}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <InfoItem
          label="Malicious"
          value={malicious}
        />

        <InfoItem
          label="Suspicious"
          value={suspicious}
        />

        <InfoItem
          label="Harmless"
          value={harmless}
        />

        <InfoItem
          label="Undetected"
          value={undetected}
        />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
        <InfoItem
          label="Moteurs d'analyse"
          value={total}
        />

        <InfoItem
          label="Réputation"
          value={reputation}
        />

        <InfoItem
          label="Dernière analyse"
          value={
            lastAnalysisDate
              ? formatDate(lastAnalysisDate)
              : null
          }
        />
      </div>

      {isMeaningfulValue(
        permalink
      ) && (
        <div className="mt-3">
          <a
            href={permalink}
            target="_blank"
            rel="noreferrer"
            className="break-all text-sm font-medium text-[var(--accent)] hover:underline"
          >
            Voir sur VirusTotal →
          </a>
        </div>
      )}
    </div>
  );
}

/* ============================================================
   ABUSEIPDB
   ============================================================ */

function AbuseIpdbCard({ item }) {
  const value =
    item?.valeur ??
    item?.value ??
    item?.ip;

  return (
    <div className="rounded-lg border border-[var(--border)] p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-semibold uppercase tracking-wide opacity-60">
          {item?.type_ioc || "IP"}
        </div>

        <span className="rounded-full border border-[var(--border)] px-2 py-1 text-xs">
          AbuseIPDB
        </span>
      </div>

      <div className="mb-4 break-all text-sm font-medium">
        {isMeaningfulValue(value)
          ? value
          : "—"}
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <InfoItem
          label="Abuse confidence"
          value={
            item?.abuse_confidence_score !==
              null &&
            item?.abuse_confidence_score !==
              undefined
              ? `${item.abuse_confidence_score}%`
              : null
          }
        />

        <InfoItem
          label="Rapports"
          value={item?.total_reports}
        />

        <InfoItem
          label="Utilisateurs distincts"
          value={
            item?.num_distinct_users
          }
        />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
        <InfoItem
          label="Pays"
          value={
            item?.country_name ||
            item?.country_code
          }
        />

        <InfoItem
          label="ISP"
          value={item?.isp}
        />

        <InfoItem
          label="Usage"
          value={item?.usage_type}
        />
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-3">
        <InfoItem
          label="Tor"
          value={
            item?.is_tor
              ? "Oui"
              : "Non"
          }
        />

        <InfoItem
          label="Dernier signalement"
          value={
            item?.last_reported_at
              ? formatDate(
                  item.last_reported_at
                )
              : null
          }
        />

        <InfoItem
          label="Vérifié le"
          value={
            item?.checked_at
              ? formatDate(
                  item.checked_at
                )
              : null
          }
        />
      </div>
    </div>
  );
}

/* ============================================================
   PAGE
   ============================================================ */

export default function AlertDetailPage() {
  const params = useParams();
  const router = useRouter();

  /*
   * ==========================================================
   * RBAC
   * ==========================================================
   */

  const {
    hasPermission,
    loading: rbacLoading,
  } = useRBAC();

  const canReadAlerts =
    hasPermission("ALERT_READ");

  const canReadEvents =
    hasPermission("EVENT_READ");

  const canCreateIncident =
    hasPermission("INCIDENT_CREATE");

  const canReadIncident =
    hasPermission("INCIDENT_READ");

  const [alert, setAlert] = useState(null);
  const [event, setEvent] = useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const [creatingCase, setCreatingCase] =
    useState(false);

  const [caseError, setCaseError] =
    useState("");

  /* ==========================================================
     LOAD ALERT
     ========================================================== */

  useEffect(() => {
    let cancelled = false;

    /*
     * Tant que le RBAC n'est pas chargé,
     * on ne lance aucune requête métier.
     */
    if (rbacLoading) {
      return;
    }

    /*
     * L'utilisateur ne peut pas consulter
     * une alerte sans ALERT_READ.
     */
    if (!canReadAlerts) {
      setLoading(false);
      return;
    }

    async function load() {
      try {
        setLoading(true);
        setError("");

        const alertData =
          await getAlert(params.id);

        if (cancelled) {
          return;
        }

        setAlert(alertData);

        /*
         * Cas 1 :
         * l'API retourne directement l'événement.
         */
        if (alertData?.evenement) {
          setEvent(
            alertData.evenement
          );
        }

        /*
         * Cas 2 :
         * on recherche l'événement uniquement
         * si l'utilisateur possède EVENT_READ.
         */
        else if (
          alertData?.identifiant_externe &&
          canReadEvents
        ) {
          try {
            const eventsData =
              await getEvents();

            const events =
              extractEvents(eventsData);

            const externalId =
              normalizeExternalId(
                alertData.identifiant_externe
              );

            const matchingEvent =
              events.find(
                (item) =>
                  normalizeExternalId(
                    getEventExternalId(
                      item
                    )
                  ) === externalId
              );

            if (
              !cancelled &&
              matchingEvent
            ) {
              setEvent(
                matchingEvent
              );
            }
          } catch {
            if (!cancelled) {
              setEvent(null);
            }
          }
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err?.message ||
              "Impossible de charger cette alerte."
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    if (params?.id) {
      load();
    }

    return () => {
      cancelled = true;
    };
  }, [
    params?.id,
    rbacLoading,
    canReadAlerts,
    canReadEvents,
  ]);

  /* ==========================================================
     CREATE INCIDENT / CASE
     ========================================================== */

  async function handleCreateCase() {
    /*
     * Protection RBAC côté frontend.
     *
     * Le backend doit également protéger
     * l'endpoint avec INCIDENT_CREATE.
     */
    if (
      !params?.id ||
      creatingCase ||
      !canCreateIncident
    ) {
      return;
    }

    try {
      setCreatingCase(true);
      setCaseError("");

      await createIncidentFromAlert(
        params.id
      );

      const refreshedAlert =
        await getAlert(params.id);

      setAlert(
        refreshedAlert
      );

      if (
        refreshedAlert?.evenement
      ) {
        setEvent(
          refreshedAlert.evenement
        );
      }
    } catch (err) {
      setCaseError(
        err?.message ||
          "Impossible de créer le Case TheHive."
      );
    } finally {
      setCreatingCase(false);
    }
  }

  /* ==========================================================
     RBAC LOADING
     ========================================================== */

  if (rbacLoading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="flex items-center gap-2.5 text-sm opacity-60">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--accent)]" />
          Vérification des permissions...
        </div>
      </div>
    );
  }

  /* ==========================================================
     ACCESS DENIED
     ========================================================== */

  if (!canReadAlerts) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <div className="rounded-xl border border-[var(--critical)] bg-[var(--critical)]/5 p-5">
          <div className="font-semibold text-[var(--critical)]">
            Accès refusé
          </div>

          <div className="mt-2 text-sm opacity-80">
            Votre compte ne possède pas la permission
            nécessaire pour consulter cette alerte.
          </div>

          <button
            type="button"
            onClick={() =>
              router.back()
            }
            className="mt-4 rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium transition-colors hover:bg-[var(--border)]/20"
          >
            Retour
          </button>
        </div>
      </div>
    );
  }

  /* ==========================================================
     LOADING
     ========================================================== */

  if (loading) {
    return (
      <div className="flex min-h-[60vh] items-center justify-center">
        <div className="flex items-center gap-2.5 text-sm opacity-60">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[var(--accent)]" />
          Chargement de l’alerte...
        </div>
      </div>
    );
  }

  /* ==========================================================
     ERROR
     ========================================================== */

  if (error) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <div className="rounded-xl border border-[var(--critical)] bg-[var(--critical)]/5 p-5">
          <div className="font-semibold text-[var(--critical)]">
            Erreur
          </div>

          <div className="mt-2 text-sm opacity-80">
            {error}
          </div>

          <button
            type="button"
            onClick={() =>
              router.back()
            }
            className="mt-4 rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium transition-colors hover:bg-[var(--border)]/20"
          >
            Retour
          </button>
        </div>
      </div>
    );
  }

  /* ==========================================================
     ALERT NOT FOUND
     ========================================================== */

  if (!alert) {
    return (
      <div className="mx-auto max-w-2xl p-6">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 text-sm opacity-70">
          Alerte introuvable.
        </div>
      </div>
    );
  }

  /* ============================================================
     DESCRIPTION / SOC PARSER
     ============================================================ */

  const description =
    String(
      alert.description || ""
    );

  const parsed =
    parseSocSummary(description);

  const classificationSection =
    getSection(
      parsed.sections,
      "Classification"
    );

  const agentSection =
    getSection(
      parsed.sections,
      "Agent & System Info",
      "Agent and System Info",
      "Agent System Info",
      "Agent & Système",
      "Agent et système"
    );

  const attackSection =
    getSection(
      parsed.sections,
      "Attack Context",
      "Contexte de l'attaque",
      "Contexte attaque"
    );

  const iocSection =
    getSection(
      parsed.sections,
      "IOC Analysis",
      "IOC",
      "Analyse IOC",
      "Analyse des IOC"
    );

  const threatSection =
    getSection(
      parsed.sections,
      "Threat Intelligence",
      "Threat Intel",
      "Renseignement sur les menaces"
    );

  const riskSection =
    getSection(
      parsed.sections,
      "Risk Assessment",
      "Risk Analyzer",
      "Évaluation du risque",
      "Evaluation du risque"
    );

  const solutionsSection =
    getSection(
      parsed.sections,
      "Solutions recommandées pour l'analyste",
      "Solutions",
      "Recommended Solutions",
      "Recommended Actions"
    );

  const classificationFields =
    parseLabeledFields(
      classificationSection
    );

  const agentFields =
    parseLabeledFields(
      agentSection
    );

  const attackFields =
    parseLabeledFields(
      attackSection
    );

  const iocFields =
    parseLabeledFields(
      iocSection
    );

  const threatFields =
    parseLabeledFields(
      threatSection
    );

  const riskFields =
    parseLabeledFields(
      riskSection
    );

  /* ============================================================
     RAW / NORMALIZED EVENT
     ============================================================ */

  const eventPayload =
    getEventPayload(event);

  const rawSource =
    safeJsonObject(
      getValue(
        event,
        "donnees_brutes",
        "raw_data",
        "rawData"
      )
    );

  const wazuhSource =
    safeJsonObject(
      rawSource?._source ||
        eventPayload?._source ||
        eventPayload
    );

  const wazuhAgent =
    safeJsonObject(
      wazuhSource?.agent
    );

  const wazuhRule =
    safeJsonObject(
      wazuhSource?.rule
    );

  const wazuhDecoder =
    safeJsonObject(
      wazuhSource?.decoder
    );

  const wazuhData =
    safeJsonObject(
      wazuhSource?.data
    );

  const rawEvent =
    Object.keys(rawSource).length > 0
      ? rawSource
      : eventPayload;

  const normalizedEventData =
    unwrapObject(
      getValue(
        event,
        "donnees_normalisees",
        "normalized_data",
        "normalizedData"
      )
    );

  const normalizedAlertData =
    getFirstObject(
      alert?.donnees_normalisees,
      alert?.normalized_data,
      alert?.normalizedData,
      alert?.donnees_normalisees?.data,
      alert?.normalized_data?.data
    );

  /* ============================================================
     CLASSIFICATION STRUCTURED DATA
     ============================================================ */

  const apiClassification =
    getFirstObject(
      alert?.classification,
      alert?.classification?.data,
      alert?.classification?.result,

      normalizedAlertData?.classification,

      normalizedEventData?.classification,

      event?.classification,
      event?.classification?.data,

      alert?.normalized_data?.classification,
      alert?.donnees_normalisees?.classification
    );

  const eventType =
    getFlexibleValue(
      apiClassification,
      "event_type",
      "eventType",
      "type_evenement",
      "type_event",
      "event_type_name"
    ) ||
    getFlexibleValue(
      alert,
      "event_type",
      "eventType",
      "type_evenement",
      "type_event"
    ) ||
    getFlexibleValue(
      event,
      "event_type",
      "eventType",
      "type_evenement",
      "type_event"
    ) ||
    getFlexibleValue(
      normalizedEventData,
      "event_type",
      "eventType",
      "type_evenement",
      "type_event"
    ) ||
    getFlexibleValue(
      normalizedAlertData,
      "event_type",
      "eventType",
      "type_evenement",
      "type_event"
    ) ||
    findNestedValueInObjects(
      [
        wazuhSource,
        rawEvent,
        wazuhData,
      ],
      [
        ["event_type"],
        ["attack_type"],
        ["event", "type"],
        ["classification"],
        ["data", "event_type"],
      ]
    ) ||
    getSummaryField(
      classificationFields,
      "Event type",
      "Type d'événement",
      "Type evenement",
      "Type",
      "Classification"
    );

  /* ============================================================
     MITRE ATT&CK
     ============================================================ */

  const mitre =
    getFirstObject(
      apiClassification?.mitre,

      apiClassification?.MITRE,

      apiClassification?.mitre_attack,

      alert?.mitre,
      alert?.mitre_attack,

      normalizedAlertData?.mitre,
      normalizedAlertData?.mitre_attack,

      normalizedEventData?.mitre,
      normalizedEventData?.mitre_attack,

      event?.mitre,
      event?.mitre_attack,

      wazuhSource?.mitre
    );

  const mitreIds =
    normalizeStringArray(
      mitre?.id ??
        mitre?.ids ??
        mitre?.mitre_id ??
        mitre?.mitre_ids ??
        apiClassification?.mitre_id ??
        apiClassification?.mitre_ids
    );

  const mitreTactics =
    normalizeStringArray(
      mitre?.tactic ??
        mitre?.tactics ??
        mitre?.mitre_tactic ??
        mitre?.mitre_tactics ??
        apiClassification?.mitre_tactic ??
        apiClassification?.mitre_tactics
    );

  const mitreTechniques =
    normalizeStringArray(
      mitre?.technique ??
        mitre?.techniques ??
        mitre?.mitre_technique ??
        mitre?.mitre_techniques ??
        apiClassification?.mitre_technique ??
        apiClassification?.mitre_techniques
    );

  const hasMitre =
    mitreIds.length > 0 ||
    mitreTactics.length > 0 ||
    mitreTechniques.length > 0;

  /* ============================================================
     CLASSIFICATION FINAL
     ============================================================ */

  const classification =
    eventType ||
    getSummaryField(
      classificationFields,
      "Event type",
      "Type d'événement",
      "Type evenement",
      "Type",
      "Classification"
    ) ||
    getValue(
      event,
      "type_evenement"
    ) ||
    findNestedValueInObjects(
      [
        normalizedEventData,
        normalizedAlertData,
        wazuhSource,
        rawEvent,
      ],
      [
        ["event_type"],
        ["event", "type"],
        ["classification"],
        ["attack_type"],
      ]
    ) ||
    "—";

  /* ============================================================
     RULE / AGENT
     ============================================================ */

  const ruleId =
    getSummaryField(
      classificationFields,
      "Rule ID",
      "Rule Id",
      "ID de règle",
      "ID règle",
      "Règle Wazuh"
    ) ||
    getValue(
      event,
      "rule_id_externe"
    ) ||
    getFlexibleValue(
      wazuhRule,
      "id",
      "rule_id"
    ) ||
    findNestedValue(
      wazuhSource,
      [
        ["rule", "id"],
        ["rule_id"],
        ["data", "rule_id"],
      ]
    );

  const sourceLocation =
    getSummaryField(
      agentFields,
      "Source Location / Log",
      "Source / Log",
      "Source Location",
      "Source",
      "Log"
    ) ||
    getValue(
      event,
      "decoder"
    ) ||
    getFlexibleValue(
      wazuhDecoder,
      "name",
      "decoder"
    );

  const agentName =
    getSummaryField(
      agentFields,
      "Agent Name",
      "Nom de l'agent",
      "Nom agent"
    ) ||
    getFlexibleValue(
      wazuhAgent,
      "name"
    ) ||
    getValue(
      event,
      "agent_name"
    );

  const agentId =
    getSummaryField(
      agentFields,
      "Agent ID",
      "ID de l'agent"
    ) ||
    getFlexibleValue(
      wazuhAgent,
      "id"
    ) ||
    getValue(
      event,
      "agent_id"
    );

  const agentIp =
    getSummaryField(
      agentFields,
      "Agent IP",
      "IP de l'agent"
    ) ||
    getFlexibleValue(
      wazuhAgent,
      "ip",
      "agent_ip"
    ) ||
    getValue(
      event,
      "agent_ip"
    );

  /* ============================================================
     ATTACK CONTEXT
     ============================================================ */

  const attackSources = [
    attackFields,
    normalizedEventData,
    normalizedAlertData,
    wazuhData,
    wazuhSource,
    rawEvent,
  ];

  const attackType =
    eventType ||
    getSummaryField(
      attackFields,
      "Attack Type",
      "Type d'attaque",
      "Attack type"
    ) ||
    getValue(
      event,
      "categorie"
    ) ||
    findNestedValueInObjects(
      attackSources,
      [
        ["attack_type"],
        ["attack", "type"],
        ["event_type"],
        ["classification"],
      ]
    );

  const requestUri =
    getSummaryField(
      attackFields,
      "Request URI",
      "URI",
      "Request URL",
      "URL de requête"
    ) ||
    findNestedValueInObjects(
      attackSources,
      [
        ["request_uri"],
        ["requestUri"],
        ["uri"],
        ["request", "uri"],
        ["http", "url"],
        ["http", "request", "uri"],
        ["http", "request", "url"],
      ]
    );

  const sourceIp =
    getSummaryField(
      attackFields,
      "Source IP",
      "IP source",
      "Src IP",
      "Source"
    ) ||
    findNestedValueInObjects(
      attackSources,
      [
        ["srcip"],
        ["src_ip"],
        ["source_ip"],
        ["source", "ip"],
        ["source", "address"],
        ["src", "ip"],
        ["client", "ip"],
        ["client_ip"],
      ]
    );

  const destinationIp =
    getSummaryField(
      attackFields,
      "Destination IP",
      "IP destination",
      "Dst IP",
      "Destination"
    ) ||
    findNestedValueInObjects(
      attackSources,
      [
        ["dstip"],
        ["dst_ip"],
        ["destination_ip"],
        ["destination", "ip"],
        ["destination", "address"],
        ["dst", "ip"],
        ["server", "ip"],
        ["server_ip"],
      ]
    );

  const networkAction =
    getSummaryField(
      attackFields,
      "Network Action",
      "Action réseau",
      "Action",
      "Firewall Action"
    ) ||
    findNestedValueInObjects(
      attackSources,
      [
        ["action"],
        ["network_action"],
        ["firewall", "action"],
      ]
    );

  /* ============================================================
     IOCS
     ============================================================ */

  const structuredIocSources = [
    normalizedEventData?.iocs,
    normalizedAlertData?.iocs,
    event?.iocs,
    alert?.iocs,
  ];

  const structuredIocLists =
    structuredIocSources
      .flatMap((value) =>
        normalizeIocList(value)
      );

  const structuredIocs =
    getFirstObject(
      normalizedEventData?.iocs,
      normalizedAlertData?.iocs,
      event?.iocs,
      alert?.iocs
    );

  const hash =
    getSummaryField(
      iocFields,
      "Hash",
      "SHA256",
      "SHA-256",
      "SHA1",
      "MD5"
    ) ||
    getFlexibleValue(
      structuredIocs,
      "hash",
      "sha256",
      "sha1",
      "md5"
    ) ||
    findNestedValueInObjects(
      [
        rawEvent,
        wazuhSource,
        wazuhData,
      ],
      [
        ["sha256"],
        ["hash"],
        ["hash_sha256"],
        ["file", "hash"],
        ["file", "sha256"],
        ["data", "sha256"],
        ["data", "hash"],
      ]
    );

  const url =
    getSummaryField(
      iocFields,
      "URL",
      "Url"
    ) ||
    getFlexibleValue(
      structuredIocs,
      "url",
      "uri"
    ) ||
    findNestedValueInObjects(
      [
        rawEvent,
        wazuhSource,
        wazuhData,
      ],
      [
        ["url"],
        ["uri"],
        ["data", "url"],
        ["http", "url"],
        ["http", "request", "url"],
      ]
    );

  const domain =
    getSummaryField(
      iocFields,
      "Domain",
      "Domaine"
    ) ||
    getFlexibleValue(
      structuredIocs,
      "domain"
    ) ||
    findNestedValueInObjects(
      [
        rawEvent,
        wazuhSource,
        wazuhData,
      ],
      [
        ["domain"],
        ["data", "domain"],
      ]
    );

  const alertIocs = [
    ...structuredIocLists,
  ];

  const parsedIocs = [];

  function addIoc(type, value) {
    if (!isMeaningfulValue(value)) {
      return;
    }

    const normalizedValue =
      String(value).trim();

    const exists =
      parsedIocs.some(
        (item) =>
          String(item.value)
            .toLowerCase() ===
          normalizedValue.toLowerCase()
      );

    if (!exists) {
      parsedIocs.push({
        type:
          type ||
          "IOC",
        value:
          normalizedValue,
      });
    }
  }

  addIoc("HASH", hash);
  addIoc("URL", url);
  addIoc("DOMAIN", domain);

  for (const ioc of alertIocs) {
    if (
      !ioc ||
      typeof ioc !== "object"
    ) {
      continue;
    }

    const value =
      getFlexibleValue(
        ioc,
        "valeur",
        "value",
        "ioc",
        "url",
        "domain",
        "hash",
        "ip"
      );

    const type =
      getFlexibleValue(
        ioc,
        "type_ioc",
        "type",
        "ioc_type",
        "typeIoc"
      );

    addIoc(
      type ||
        "IOC",
      value
    );
  }

  addIoc(
    "IP",
    getFlexibleValue(
      normalizedEventData,
      "ip"
    )
  );

  addIoc(
    "DOMAIN",
    getFlexibleValue(
      normalizedEventData,
      "domain"
    )
  );

  const hasIoc =
    parsedIocs.length > 0;

  /* ============================================================
     THREAT INTELLIGENCE
     ============================================================ */

  const normalizedThreatIntelligence =
    normalizeThreatIntelligence(
      alert.threat_intelligence ??
        alert.threatIntelligence ??
        normalizedAlertData?.threat_intelligence ??
        normalizedEventData?.threat_intelligence
    );

  const virusTotal =
    normalizedThreatIntelligence
      .virustotal;

  const abuseIpdb =
    normalizedThreatIntelligence
      .abuseipdb;

  const hasVirusTotal =
    virusTotal.length > 0;

  const hasAbuseIpdb =
    abuseIpdb.length > 0;

  const threatAvailable =
    hasVirusTotal ||
    hasAbuseIpdb;

  /* ============================================================
     LEGACY THREAT INTELLIGENCE FALLBACK
     ============================================================ */

  const vtRaw =
    getSummaryField(
      threatFields,
      "VirusTotal",
      "VT"
    ) || "";

  const abuseRaw =
    getSummaryField(
      threatFields,
      "AbuseIPDB"
    ) || "";

  /* ============================================================
     RISK
     ============================================================ */

  const evaluation =
    getFirstObject(
      alert.evaluation_risque,
      alert.evaluationRisque,
      alert.risk_assessment,
      alert.riskAssessment,

      normalizedAlertData?.evaluation_risque,
      normalizedAlertData?.risk,

      normalizedEventData?.evaluation_risque,
      normalizedEventData?.risk
    );

  const riskScore =
    getFlexibleValue(
      evaluation,
      "score_risque",
      "score",
      "risk_score",
      "riskScore"
    ) ??
    getSummaryField(
      riskFields,
      "Score",
      "Risk Score"
    );

  const rawRiskLevel =
    getFlexibleValue(
      evaluation,
      "niveau_risque",
      "level",
      "niveau",
      "risk_level",
      "riskLevel"
    ) ??
    getSummaryField(
      riskFields,
      "Level",
      "Niveau",
      "Risk Level"
    );

  const normalizedRiskLevel =
    normalizeRiskLevel(
      rawRiskLevel
    );

  const riskLevel =
    normalizedRiskLevel ||
    (
      isMeaningfulValue(
        rawRiskLevel
      )
        ? rawRiskLevel
        : alert.severite
    );

  const recommendedAction =
    getFlexibleValue(
      evaluation,
      "action_recommandee",
      "action",
      "recommended_action",
      "recommendedAction"
    ) ??
    getSummaryField(
      riskFields,
      "Action",
      "Action recommandée",
      "Recommended Action"
    );

  const riskReason =
    getFlexibleValue(
      evaluation,
      "raison",
      "reason",
      "risk_reason",
      "riskReason"
    ) ??
    getSummaryField(
      riskFields,
      "Reason",
      "Raison"
    );

  const forceCaseValue =
    getFlexibleValue(
      evaluation,
      "force_case",
      "forceCase"
    );

  const forceCase =
    forceCaseValue !== null &&
    forceCaseValue !== undefined
      ? Boolean(
          forceCaseValue === true ||
            forceCaseValue === 1 ||
            forceCaseValue === "1" ||
            forceCaseValue === "true"
        )
      : /case forcée|force case/i.test(
          riskSection
        );

  /* ============================================================
     INCIDENT / THEHIVE
     ============================================================ */

  const incident =
    getFirstObject(
      alert.incident,
      alert.incident_data,
      alert.incidentData
    );

  const incidentId =
    getValue(
      incident,
      "id_incident"
    ) ||
    getValue(
      alert,
      "id_incident",
      "identifiant_incident"
    );

  const theHive =
    getFirstObject(
      alert.thehive,
      alert.theHive,
      alert.thehive_data
    );

  const theHiveId =
    getValue(
      theHive,
      "identifiant",
      "identifiant_thehive",
      "case_id",
      "caseId"
    ) ||
    getValue(
      alert,
      "identifiant_thehive",
      "thehive_id",
      "theHiveId"
    ) ||
    getValue(
      incident,
      "identifiant_thehive"
    );

  /* ============================================================
     EVENT METADATA
     ============================================================ */

  const eventExternalId =
    normalizeExternalId(
      getEventExternalId(event)
    );

  const alertExternalId =
    normalizeExternalId(
      alert.identifiant_externe
    );

  const eventTimestamp =
    getValue(
      event,
      "timestamp_evenement"
    ) ||
    getValue(
      wazuhSource,
      "timestamp"
    );

  const eventDescription =
    getValue(
      event,
      "description"
    ) ||
    getValue(
      wazuhRule,
      "description"
    ) ||
    alert.titre;

  const solutions =
    extractSolutionLines(
      solutionsSection
    );

  const incidentAvailable =
    Boolean(incidentId);

  const eventAvailable =
    Boolean(event);

  const sourceAlert =
    isMeaningfulValue(
      alert.source_alerte
    )
      ? alert.source_alerte
      : "—";

  const wazuhNativeSeverity =
    getValue(
      event,
      "severite"
    ) ||
    getValue(
      event,
      "niveau_wazuh"
    ) ||
    getValue(
      wazuhRule,
      "level"
    ) ||
    alert.severite;

  /*
   * Création manuelle autorisée uniquement si
   * l'utilisateur possède INCIDENT_CREATE.
   */
  const manualCaseAllowed =
    canCreateIncident &&
    !theHiveId &&
    String(
      recommendedAction || ""
    ).toUpperCase() !==
      "CREATE_CASE";

  const summary =
    parsed.summary ||
    cleanMarkdown(
      alert.titre ||
        "Aucune description disponible."
    );

  /* ============================================================
     RENDER
     ============================================================ */

  return (
    <div className="mx-auto max-w-6xl space-y-5 p-6">

      {/* ======================================================
          HEADER
          ====================================================== */}

      <div className="flex flex-col gap-4 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-5 sm:p-6 lg:flex-row lg:items-start lg:justify-between">

        <div className="min-w-0">

          <button
            type="button"
            onClick={() =>
              router.back()
            }
            className="mb-4 flex items-center gap-1 text-sm opacity-55 transition-opacity hover:opacity-100"
          >
            ← Retour
          </button>

          <div className="flex flex-wrap items-center gap-2">

            <SeverityBadge
              severity={riskLevel}
            />

            <StatusBadge
              status={alert.statut}
            />

          </div>

          <h1 className="mt-3 break-words text-xl font-bold tracking-tight sm:text-2xl">
            {alert.titre}
          </h1>

          <div className="mt-1.5 text-sm opacity-55">
            Alerte SOC
          </div>

        </div>

        <div className="flex flex-wrap gap-2">

          {theHiveId && (
            <a
              href={THEHIVE_URL}
              target="_blank"
              rel="noreferrer"
              className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium transition-colors hover:bg-[var(--border)]/20"
            >
              Ouvrir TheHive
            </a>
          )}

          {manualCaseAllowed && (
            <button
              type="button"
              onClick={handleCreateCase}
              disabled={creatingCase}
              className="rounded-lg border border-[var(--accent)] bg-[var(--accent)]/5 px-4 py-2 text-sm font-medium text-[var(--accent)] transition-colors hover:bg-[var(--accent)]/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {creatingCase
                ? "Création du Case..."
                : "Créer un Case TheHive"}
            </button>
          )}

          {incidentAvailable &&
            canReadIncident && (
              <button
                type="button"
                onClick={() =>
                  router.push(
                    `/incidents/${incidentId}`
                  )
                }
                className="rounded-lg border border-[var(--border)] px-4 py-2 text-sm font-medium transition-colors hover:bg-[var(--border)]/20"
              >
                Voir l’incident
              </button>
            )}

        </div>

      </div>

      {caseError && (
        <div className="rounded-lg border border-[var(--critical)] bg-[var(--critical)]/5 p-3 text-sm text-[var(--critical)]">
          {caseError}
        </div>
      )}

      {/* ======================================================
          SUMMARY
          ====================================================== */}

      <Section title="Résumé SOC">

        <div className="rounded-lg border border-[var(--border)] p-4">
          <p className="text-sm leading-6">
            {summary ||
              "Aucun résumé disponible."}
          </p>
        </div>

      </Section>

      {/* ======================================================
          CLASSIFICATION + AGENT
          ====================================================== */}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">

        <Section title="Classification">

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

            <InfoItem
              label="Type d'événement"
              value={classification}
            />

            <InfoItem
              label="Règle Wazuh"
              value={ruleId}
            />

            <InfoItem
              label="Source de l'alerte"
              value={sourceAlert}
            />

            <InfoItem
              label="Identifiant externe"
              value={alertExternalId}
            />

          </div>

        </Section>

        <Section title="Agent & système">

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

            <InfoItem
              label="Nom agent"
              value={agentName}
            />

            <InfoItem
              label="ID agent"
              value={agentId}
            />

            <InfoItem
              label="IP agent"
              value={agentIp}
            />

            <InfoItem
              label="Source / Log"
              value={sourceLocation}
            />

          </div>

        </Section>

      </div>

      {/* ======================================================
          ATTACK CONTEXT
          ====================================================== */}

      <Section title="Contexte de l'attaque">

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">

          <InfoItem
            label="Type d'attaque"
            value={attackType}
          />

          <InfoItem
            label="Request URI"
            value={requestUri}
          />

          <InfoItem
            label="IP source"
            value={sourceIp}
          />

          <InfoItem
            label="IP destination"
            value={destinationIp}
          />

          <InfoItem
            label="Action réseau"
            value={networkAction}
          />

          <InfoItem
            label="Classification"
            value={classification}
          />

        </div>

      </Section>

      {/* ======================================================
          MITRE ATT&CK
          ====================================================== */}

      <Section title="MITRE ATT&CK">

        {hasMitre ? (
          <div className="grid grid-cols-1 gap-x-8 gap-y-4 md:grid-cols-3">

            {mitreIds.length > 0 && (
              <InfoItem
                label="Identifiants MITRE"
                value={mitreIds.join(", ")}
              />
            )}

            {mitreTechniques.length > 0 && (
              <InfoItem
                label="Techniques"
                value={mitreTechniques.join(", ")}
              />
            )}

            {mitreTactics.length > 0 && (
              <InfoItem
                label="Tactiques"
                value={mitreTactics.join(", ")}
              />
            )}

          </div>
        ) : (
          <div className="text-sm opacity-60">
            Aucune information MITRE ATT&CK disponible.
          </div>
        )}

      </Section>

      {/* ======================================================
          IOC ANALYSIS
          ====================================================== */}

      <Section title="IOC Analysis">

        {hasIoc ? (
          <div className="space-y-3">

            <div className="mb-3 text-sm opacity-70">
              {parsedIocs.length} IOC
              {parsedIocs.length > 1
                ? "s"
                : ""}{" "}
              détecté
              {parsedIocs.length > 1
                ? "s"
                : ""}.
            </div>

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">

              {parsedIocs.map(
                (ioc, index) => (
                  <div
                    key={`${ioc.type}-${ioc.value}-${index}`}
                    className="rounded-lg border border-[var(--border)] p-4"
                  >

                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide opacity-60">
                      {ioc.type}
                    </div>

                    <div className="break-all text-sm">
                      {ioc.value}
                    </div>

                  </div>
                )
              )}

            </div>

          </div>
        ) : (
          <div className="rounded-lg border border-[var(--border)] p-4 text-sm opacity-60">
            Aucun IOC détecté.
          </div>
        )}

      </Section>

      {/* ======================================================
          THREAT INTELLIGENCE
          ====================================================== */}

      <Section title="Threat Intelligence">

        {!threatAvailable ? (
          <div className="rounded-lg border border-[var(--border)] p-4 text-sm opacity-60">
            Aucune donnée Threat Intelligence disponible.
          </div>
        ) : (
          <div className="space-y-6">

            {hasVirusTotal && (
              <div>

                <div className="mb-3 flex items-center justify-between">

                  <div className="text-sm font-semibold">
                    VirusTotal
                  </div>

                  <span className="rounded-full border border-[var(--border)] px-2.5 py-1 text-xs">
                    {virusTotal.length} IOC
                    {virusTotal.length > 1
                      ? "s"
                      : ""}
                  </span>

                </div>

                <div className="grid grid-cols-1 gap-3">

                  {virusTotal.map(
                    (item, index) => (
                      <VirusTotalCard
                        key={
                          item.id_ti_vt ||
                          `${item.type_ioc}-${item.valeur}-${index}`
                        }
                        item={item}
                      />
                    )
                  )}

                </div>

              </div>
            )}

            {hasAbuseIpdb && (
              <div>

                <div className="mb-3 flex items-center justify-between">

                  <div className="text-sm font-semibold">
                    AbuseIPDB
                  </div>

                  <span className="rounded-full border border-[var(--border)] px-2.5 py-1 text-xs">
                    {abuseIpdb.length} IOC
                    {abuseIpdb.length > 1
                      ? "s"
                      : ""}
                  </span>

                </div>

                <div className="grid grid-cols-1 gap-3">

                  {abuseIpdb.map(
                    (item, index) => (
                      <AbuseIpdbCard
                        key={
                          item.id_ti_abuse ||
                          `${item.type_ioc}-${item.valeur}-${index}`
                        }
                        item={item}
                      />
                    )
                  )}

                </div>

              </div>
            )}

            {!hasVirusTotal &&
              !hasAbuseIpdb &&
              (vtRaw || abuseRaw) && (
                <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">

                  <div className="rounded-lg border border-[var(--border)] p-4">

                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide opacity-60">
                      VirusTotal
                    </div>

                    <div className="text-sm">
                      {vtRaw ||
                        "Aucun résultat."}
                    </div>

                  </div>

                  <div className="rounded-lg border border-[var(--border)] p-4">

                    <div className="mb-2 text-xs font-semibold uppercase tracking-wide opacity-60">
                      AbuseIPDB
                    </div>

                    <div className="text-sm">
                      {abuseRaw ||
                        "Aucun résultat."}
                    </div>

                  </div>

                </div>
              )}

          </div>
        )}

      </Section>

      {/* ======================================================
          RISK ASSESSMENT
          ====================================================== */}

      <Section title="Risk Assessment">

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">

          <InfoItem
            label="Score"
            value={
              riskScore !== null &&
              riskScore !== undefined
                ? `${riskScore}/100`
                : null
            }
          />

          <InfoItem
            label="Niveau"
            value={riskLevel}
          />

          <InfoItem
            label="Action"
            value={recommendedAction}
          />

          <InfoItem
            label="Case forcée"
            value={
              forceCase
                ? "Oui"
                : "Non"
            }
          />

        </div>

        {riskReason && (
          <div className="mt-3 rounded-lg border border-[var(--border)] p-4">

            <div className="mb-2 text-xs font-semibold uppercase tracking-wide opacity-60">
              Raison
            </div>

            <div className="text-sm leading-6">
              {cleanMarkdown(
                riskReason
              )}
            </div>

          </div>
        )}

      </Section>

      {/* ======================================================
          SOLUTIONS
          ====================================================== */}

      {solutions.length > 0 && (
        <Section title="Solutions recommandées pour l'analyste">

          <ul className="space-y-2">

            {solutions.map(
              (solution, index) => (
                <li
                  key={`${solution}-${index}`}
                  className="rounded-lg border border-[var(--border)] p-3 text-sm"
                >
                  {solution}
                </li>
              )
            )}

          </ul>

        </Section>
      )}

      {/* ======================================================
          INVESTIGATION SOC
          ====================================================== */}

      <Section title="Investigation SOC">

        <div className="space-y-3">

          <InvestigationStep
            title="IOC"
            status={
              hasIoc
                ? "Disponible"
                : "En attente"
            }
            available={hasIoc}
          >
            {hasIoc && (
              <div className="text-sm opacity-80">
                {parsedIocs.length} IOC
                détecté
                {parsedIocs.length > 1
                  ? "s"
                  : ""}{" "}
                dans les données d'enrichissement.
              </div>
            )}
          </InvestigationStep>

          <InvestigationStep
            title="MITRE ATT&CK"
            status={
              hasMitre
                ? "Disponible"
                : "En attente"
            }
            available={hasMitre}
          >
            {hasMitre && (
              <div className="space-y-3">

                {mitreIds.length > 0 && (
                  <InfoItem
                    label="IDs"
                    value={mitreIds.join(", ")}
                  />
                )}

                {mitreTechniques.length > 0 && (
                  <InfoItem
                    label="Techniques"
                    value={mitreTechniques.join(", ")}
                  />
                )}

                {mitreTactics.length > 0 && (
                  <InfoItem
                    label="Tactiques"
                    value={mitreTactics.join(", ")}
                  />
                )}

              </div>
            )}
          </InvestigationStep>

          <InvestigationStep
            title="Threat Intelligence"
            status={
              threatAvailable
                ? "Disponible"
                : "En attente"
            }
            available={threatAvailable}
          >

            {threatAvailable ? (
              <div className="space-y-5">

                {hasVirusTotal && (
                  <div>

                    <div className="mb-3 font-medium">
                      VirusTotal
                    </div>

                    <div className="space-y-3">

                      {virusTotal.map(
                        (item, index) => {

                          const itemValue =
                            item.valeur ??
                            item.value ??
                            item.url ??
                            item.domain ??
                            item.hash;

                          return (
                            <div
                              key={
                                item.id_ti_vt ||
                                `vt-${index}`
                              }
                              className="rounded-lg border border-[var(--border)] p-4"
                            >

                              <div className="mb-3 break-all text-sm font-medium">

                                <span className="mr-2 text-xs uppercase opacity-60">
                                  {item.type_ioc ||
                                    item.type ||
                                    "IOC"}
                                  :
                                </span>

                                {isMeaningfulValue(
                                  itemValue
                                )
                                  ? itemValue
                                  : "—"}

                              </div>

                              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">

                                <InfoItem
                                  label="Malicious"
                                  value={
                                    item.malicious_count ??
                                    item.malicious ??
                                    0
                                  }
                                />

                                <InfoItem
                                  label="Suspicious"
                                  value={
                                    item.suspicious_count ??
                                    item.suspicious ??
                                    0
                                  }
                                />

                                <InfoItem
                                  label="Harmless"
                                  value={
                                    item.harmless_count ??
                                    item.harmless ??
                                    0
                                  }
                                />

                                <InfoItem
                                  label="Undetected"
                                  value={
                                    item.undetected_count ??
                                    item.undetected ??
                                    0
                                  }
                                />

                              </div>

                            </div>
                          );
                        }
                      )}

                    </div>

                  </div>
                )}

                {hasAbuseIpdb && (
                  <div>

                    <div className="mb-3 font-medium">
                      AbuseIPDB
                    </div>

                    <div className="space-y-3">

                      {abuseIpdb.map(
                        (item, index) => {

                          const itemValue =
                            item.valeur ??
                            item.value ??
                            item.ip;

                          return (
                            <div
                              key={
                                item.id_ti_abuse ||
                                `abuse-${index}`
                              }
                              className="rounded-lg border border-[var(--border)] p-4"
                            >

                              <div className="mb-3 break-all text-sm font-medium">

                                <span className="mr-2 text-xs uppercase opacity-60">
                                  {item.type_ioc ||
                                    "IP"}
                                  :
                                </span>

                                {isMeaningfulValue(
                                  itemValue
                                )
                                  ? itemValue
                                  : "—"}

                              </div>

                              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">

                                <InfoItem
                                  label="Score Abuse Confidence"
                                  value={
                                    item.abuse_confidence_score !==
                                      null &&
                                    item.abuse_confidence_score !==
                                      undefined
                                      ? `${item.abuse_confidence_score}%`
                                      : null
                                  }
                                />

                                <InfoItem
                                  label="Rapports"
                                  value={
                                    item.total_reports
                                  }
                                />

                                <InfoItem
                                  label="Utilisateurs distincts"
                                  value={
                                    item.num_distinct_users
                                  }
                                />

                              </div>

                            </div>
                          );
                        }
                      )}

                    </div>

                  </div>
                )}

              </div>
            ) : (
              <div className="text-sm opacity-60">
                Aucune donnée Threat Intelligence disponible.
              </div>
            )}

          </InvestigationStep>

          <InvestigationStep
            title="Risk Analyzer"
            status={
              riskScore !== null ||
              riskLevel ||
              recommendedAction
                ? "Disponible"
                : "En attente"
            }
            available={
              Boolean(
                riskScore !== null ||
                riskLevel ||
                recommendedAction
              )
            }
          >

            {(riskScore !== null ||
              riskLevel ||
              recommendedAction) && (
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">

                <InfoItem
                  label="Score"
                  value={
                    riskScore !== null &&
                    riskScore !== undefined
                      ? `${riskScore}/100`
                      : null
                  }
                />

                <InfoItem
                  label="Niveau"
                  value={riskLevel}
                />

                <InfoItem
                  label="Action"
                  value={recommendedAction}
                />

              </div>
            )}

          </InvestigationStep>

          <InvestigationStep
            title="Incident"
            status={
              incidentAvailable
                ? "Disponible"
                : "En attente"
            }
            available={
              incidentAvailable
            }
          >

            {incidentAvailable && (
              <div className="space-y-3">

                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

                  <InfoItem
                    label="ID incident"
                    value={
                      incident.id_incident
                    }
                  />

                  <InfoItem
                    label="Titre"
                    value={
                      incident.titre
                    }
                  />

                  <InfoItem
                    label="Sévérité"
                    value={
                      incident.severite
                    }
                  />

                  <InfoItem
                    label="Priorité"
                    value={
                      incident.priorite
                    }
                  />

                  <InfoItem
                    label="Statut"
                    value={
                      incident.statut
                    }
                  />

                </div>

                {canReadIncident && (
                  <button
                    type="button"
                    onClick={() =>
                      router.push(
                        `/incidents/${incidentId}`
                      )
                    }
                    className="text-sm font-medium text-[var(--accent)]"
                  >
                    Voir l'incident →
                  </button>
                )}

              </div>
            )}

          </InvestigationStep>

          <InvestigationStep
            title="TheHive"
            status={
              theHiveId
                ? "Disponible"
                : "En attente"
            }
            available={
              Boolean(theHiveId)
            }
          >

            {theHiveId ? (
              <div className="space-y-3">

                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

                  <InfoItem
                    label="Case TheHive"
                    value={
                      theHiveId
                    }
                  />

                  <InfoItem
                    label="État"
                    value="Case associée"
                  />

                </div>

                <a
                  href={THEHIVE_URL}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-block text-sm font-medium text-[var(--accent)] hover:underline"
                >
                  Ouvrir le Case dans TheHive →
                </a>

              </div>
            ) : manualCaseAllowed ? (
              <div className="space-y-3">

                <div className="text-sm opacity-70">
                  Aucun Case TheHive n'est actuellement
                  associé à cette alerte.
                </div>

                <button
                  type="button"
                  onClick={
                    handleCreateCase
                  }
                  disabled={
                    creatingCase
                  }
                  className="rounded-lg border border-[var(--accent)] px-4 py-2 text-sm font-medium text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {creatingCase
                    ? "Création du Case..."
                    : "Créer un Case TheHive"}
                </button>

                {caseError && (
                  <div className="rounded-lg border border-[var(--critical)] p-3 text-sm">
                    {caseError}
                  </div>
                )}

              </div>
            ) : (
              <div className="text-sm opacity-60">
                Création automatique du Case en attente.
              </div>
            )}

          </InvestigationStep>

        </div>

      </Section>

      {/* ======================================================
          TIMELINE
          ====================================================== */}

      <Section title="Chronologie">

        <div className="space-y-1">

          <TimelineItem
            title="Alerte créée"
            date={
              alert.date_creation
            }
            description={
              alert.titre
            }
            active
          />

          {alert.date_mise_a_jour &&
            alert.date_mise_a_jour !==
              alert.date_creation && (
              <TimelineItem
                title="Alerte mise à jour"
                date={
                  alert.date_mise_a_jour
                }
                description="Les données de l'alerte ont été mises à jour."
              />
            )}

          {eventAvailable && (
            <TimelineItem
              title="Événement Wazuh associé"
              date={
                eventTimestamp
              }
              description={
                eventExternalId
                  ? `Événement ${eventExternalId}`
                  : eventDescription
              }
            />
          )}

          {incidentAvailable && (
            <TimelineItem
              title="Incident créé"
              date={
                incident.date_creation
              }
              description={
                incident.titre
              }
            />
          )}

          {theHiveId && (
            <TimelineItem
              title="Case TheHive associée"
              date={
                incident.date_mise_a_jour
              }
              description={`Case ${theHiveId}`}
            />
          )}

          {alert.date_cloture && (
            <TimelineItem
              title="Alerte clôturée"
              date={
                alert.date_cloture
              }
              description="L'alerte a été clôturée."
            />
          )}

        </div>

      </Section>

      {/* ======================================================
          WAZUH EVENT
          ====================================================== */}

      <Section title="Événement Wazuh">

        {eventAvailable ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">

            <InfoItem
              label="Identifiant événement"
              value={
                eventExternalId
              }
            />

            <InfoItem
              label="Agent"
              value={
                agentName
              }
            />

            <InfoItem
              label="Agent ID"
              value={
                agentId
              }
            />

            <InfoItem
              label="Agent IP"
              value={
                agentIp
              }
            />

            <InfoItem
              label="Règle"
              value={
                ruleId
              }
            />

            <InfoItem
              label="Niveau Wazuh"
              value={
                getValue(
                  event,
                  "niveau_wazuh"
                ) ||
                getValue(
                  wazuhRule,
                  "level"
                )
              }
            />

            <InfoItem
              label="Decoder"
              value={
                getValue(
                  event,
                  "decoder"
                ) ||
                getValue(
                  wazuhDecoder,
                  "name"
                )
              }
            />

            <InfoItem
              label="Type"
              value={
                classification
              }
            />

            <InfoItem
              label="Sévérité Wazuh"
              value={
                wazuhNativeSeverity
              }
            />

            <InfoItem
              label="Timestamp événement"
              value={
                eventTimestamp
              }
            />

          </div>
        ) : (
          <div className="rounded-lg border border-[var(--border)] p-4">

            <div className="text-sm font-medium">
              Aucun événement associé
            </div>

            <div className="mt-1 text-sm opacity-60">
              L'alerte existe dans la base SOC mais aucun
              événement Wazuh correspondant n'est actuellement
              lié à cette alerte.
            </div>

            {alertExternalId && (
              <div className="mt-3 break-all text-xs opacity-50">
                Identifiant externe :
                {" "}
                {alertExternalId}
              </div>
            )}

          </div>
        )}

      </Section>

      {/* ======================================================
          RAW WAZUH
          ====================================================== */}

      <Section title="Données brutes Wazuh">

        {eventAvailable &&
        Object.keys(rawEvent).length > 0 ? (
          <pre className="max-h-[600px] overflow-auto rounded-lg border border-[var(--border)] bg-black/20 p-4 font-mono text-xs leading-5">
            {JSON.stringify(
              rawEvent,
              null,
              2
            )}
          </pre>
        ) : (
          <div className="space-y-3">

            <div className="rounded-lg border border-[var(--border)] p-4 text-sm opacity-60">
              Aucun événement Wazuh brut n'est associé
              directement à cette alerte.
            </div>

            {description && (
              <pre className="max-h-[500px] overflow-auto whitespace-pre-wrap rounded-lg border border-[var(--border)] bg-black/20 p-4 font-mono text-xs leading-5">
                {description}
              </pre>
            )}

          </div>
        )}

      </Section>

      {/* ======================================================
          ALERT METADATA
          ====================================================== */}

      <Section title="Métadonnées de l'alerte">

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">

          <InfoItem
            label="ID alerte"
            value={
              alert.id_alerte
            }
          />

          <InfoItem
            label="Identifiant externe"
            value={
              alert.identifiant_externe
            }
          />

          <InfoItem
            label="Source"
            value={
              sourceAlert
            }
          />

          <InfoItem
            label="Sévérité Wazuh"
            value={
              alert.severite
            }
          />

          <InfoItem
            label="Risque SOC"
            value={
              riskLevel
            }
          />

          <InfoItem
            label="Statut"
            value={
              alert.statut
            }
          />

          <InfoItem
            label="TheHive"
            value={
              theHiveId
            }
          />

          <InfoItem
            label="Création"
            value={
              formatDate(
                alert.date_creation
              )
            }
          />

          <InfoItem
            label="Mise à jour"
            value={
              formatDate(
                alert.date_mise_a_jour
              )
            }
          />

          <InfoItem
            label="Clôture"
            value={
              formatDate(
                alert.date_cloture
              )
            }
          />

          <InfoItem
            label="Règle de détection"
            value={
              alert.id_regle_detection
            }
          />

          <InfoItem
            label="Règle de corrélation"
            value={
              alert.id_regle_correlation
            }
          />

          <InfoItem
            label="Utilisateur créateur"
            value={
              alert.id_utilisateur_createur
            }
          />

        </div>

      </Section>

    </div>
  );
}