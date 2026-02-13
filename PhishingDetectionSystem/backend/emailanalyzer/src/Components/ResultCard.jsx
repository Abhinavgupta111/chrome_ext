import React from "react";
import DonutProgress from "./DonutProgress.jsx";
import { ShieldCheck, AlertTriangle, MailWarning, Server, BarChart3 } from "lucide-react";

const ResultCard = ({ result }) => {
  if (!result) return null;

  const {
    overall_score,
    risk_level,
    spf,
    dkim,
    dmarc,
    originating_ip,
    component_scores,
  } = result;

  const rawScore = Number(overall_score) ?? 0;
  const riskValue = Math.max(0, Math.min(100, rawScore <= 10 ? rawScore * 10 : rawScore));

  const normalizedCategory = (risk_level || "").toString().toLowerCase();

  const getRiskLabel = (value) => {
    if (value < 35) return "Low Risk";
    if (value < 70) return "Medium Risk";
    return "High Risk";
  };

  const getRiskBadge = (value) => {
    if (value < 35) return "bg-emerald-50 text-emerald-700 border-emerald-200";
    if (value < 70) return "bg-amber-50 text-amber-700 border-amber-200";
    return "bg-rose-50 text-rose-700 border-rose-200";
  };

  const getAuthBadge = (status) => {
    const safeStatus = String(status || "unknown").toLowerCase();

    if (safeStatus.includes("pass")) {
      return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
    if (safeStatus.includes("fail")) {
      return "bg-red-50 text-red-700 border-red-200";
    }
    if (safeStatus.includes("neutral")) {
      return "bg-yellow-50 text-yellow-700 border-yellow-200";
    }
    if (safeStatus.includes("none")) {
      return "bg-slate-50 text-slate-600 border-slate-200";
    }

    return "bg-gray-50 text-gray-600 border-gray-200";
  };
  const extractStatus = (value) => {
    if (typeof value === "boolean") return value ? "Pass" : "Fail";
    if (value === null || value === undefined) return "Unknown";
    if (typeof value === "string") return value;

    if (typeof value === "object") {
      if (value.status) return value.status;
      if (value.result) return value.result;
      if (value.verdict) return value.verdict;
      if (value.message) return value.message;

      // agar dict ke andar "pass/fail" direct value me ho
      const joined = JSON.stringify(value).toLowerCase();
      if (joined.includes("pass")) return "Pass";
      if (joined.includes("fail")) return "Fail";

      return "Unknown";
    }

    return String(value);
  };



  return (
    <div className="space-y-10">
      {/* Section title */}
      <div className="text-center md:text-left">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-(--muted-text) sm:text-sm">
          Risk Summary
        </p>

        <h3 className="mt-2 text-2xl font-semibold tracking-tight md:text-[26px]">
          Email Security Report
        </h3>

        <p className="mt-2 text-sm text-(--muted-text) sm:text-base">
          Quick breakdown of authenticity and risk indicators.
        </p>
      </div>

      {/* Main grid */}
      <div className="grid gap-8 lg:grid-cols-[minmax(0,2fr)_minmax(0,1.2fr)] xl:gap-10">

        {/* Left */}
        <div className="space-y-8">

          {/* Risk Score */}
          <div className="mx-auto w-full rounded-4xl border border-indigo-100 bg-linear-to-r from-indigo-50 via-white to-purple-50 p-px shadow-xl shadow-indigo-100/80 transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl">
            <div className="flex flex-col items-start justify-between gap-6 rounded-[28px] bg-(--card-bg)/95 px-6 py-6 sm:flex-row sm:px-8 sm:py-7 lg:px-10 lg:py-8">
              <div>
                <p className="text-base font-semibold text-slate-900 sm:text-lg md:text-xl">
                  Risk Score
                </p>
                <p className="mt-1 text-sm text-slate-500 sm:text-[15px] md:text-base">
                  Based on sender trust + phishing indicators.
                </p>

                <p className="mt-2 text-xs font-medium text-slate-500 sm:text-[13px]">
                  0 = safest, 100 = highest risk
                </p>

                <span
                  className={`mt-3 inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold ${getRiskBadge(
                    riskValue
                  )}`}
                >
                  {risk_level || getRiskLabel(riskValue)}
                </span>
              </div>

              <div className="shrink-0 self-center scale-100 md:scale-105">
                <DonutProgress score={riskValue} />
              </div>
            </div>
          </div>

          {/* Cards Grid */}
          <div className="grid gap-6 md:grid-cols-2 lg:gap-8">

            {/* Authentication Checks */}
            <div className="min-h-56 rounded-3xl border border-gray-200/80 bg-(--card-bg)/95 p-6 shadow-md shadow-indigo-100/70 backdrop-blur-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl md:p-8">
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm md:text-[13px]">
                Authentication Checks
              </p>

              <div className="mt-5 space-y-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold text-slate-700 sm:text-base md:text-[17px]">
                    SPF
                  </p>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-semibold ${getAuthBadge(
                      extractStatus(spf)
                    )}`}
                  >
                    {extractStatus(spf)}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold text-slate-700 sm:text-base md:text-[17px]">
                    DKIM
                  </p>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-semibold ${getAuthBadge(
                      extractStatus(dkim)
                    )}`}
                  >
                    {extractStatus(dkim)}
                  </span>
                </div>


                <div className="flex items-center justify-between">
                  <p className="text-sm font-semibold text-slate-700 sm:text-base md:text-[17px]">
                    DMARC
                  </p>

                  <span
                    className={`rounded-full border px-3 py-1 text-xs font-semibold ${getAuthBadge(
                      extractStatus(dmarc)
                    )}`}
                  >
                    {extractStatus(dmarc)}
                  </span>
                </div>
              </div>
            </div>

            {/* Originating IP */}
            <div className="min-h-56 rounded-3xl border border-gray-200/80 bg-(--card-bg)/95 p-6 shadow-md shadow-indigo-100/70 backdrop-blur-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl md:p-8">
              <div className="flex items-center gap-2">
                <Server className="h-5 w-5 text-indigo-600" />
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm md:text-[13px]">
                  Infrastructure Info
                </p>
              </div>

              <div className="mt-6 space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <p className="text-sm font-semibold text-slate-700 sm:text-base md:text-[17px]">
                    Originating IP
                  </p>

                  <p className="max-w-55 truncate text-right font-mono text-xs text-slate-900 sm:text-sm md:text-[15px]">
                    {originating_ip || "Not found"}
                  </p>
                </div>

                <div className="rounded-2xl border border-indigo-100 bg-indigo-50/70 p-4 text-sm text-slate-700">
                  <p className="text-xs font-semibold uppercase tracking-wider text-indigo-700">
                    Why it matters?
                  </p>
                  <p className="mt-2 text-[13px] leading-relaxed text-slate-600">
                    This IP indicates the server that actually sent the email. Suspicious IPs
                    can reveal spoofing or malicious infrastructure.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Component Scores */}
          <div className="rounded-3xl border border-gray-200/80 bg-(--card-bg)/95 p-6 shadow-md shadow-indigo-100/70 backdrop-blur-sm transition-all duration-300 hover:-translate-y-1 hover:shadow-2xl md:p-8">
            <div className="flex items-center gap-2">
              <BarChart3 className="h-5 w-5 text-purple-600" />
              <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 sm:text-sm md:text-[13px]">
                Component Scores
              </p>
            </div>

            <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {component_scores &&
                Object.entries(component_scores).map(([key, value]) => (
                  <div
                    key={key}
                    className="rounded-2xl border border-slate-200 bg-white/70 p-4 shadow-sm"
                  >
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                      {key.replaceAll("_", " ")}
                    </p>

                    <p className="mt-2 text-lg font-bold text-slate-900">
                      {typeof value === "number" ? value.toFixed(2) : value}
                    </p>
                  </div>
                ))}
            </div>

            {!component_scores && (
              <p className="mt-4 text-sm text-slate-500">
                No component score breakdown available.
              </p>
            )}
          </div>

          <div className="flex items-start justify-between gap-3">
            <p className="text-sm font-semibold text-slate-700 sm:text-base md:text-[17px]">
              Category
            </p>
            <span className="rounded-full bg-slate-900 px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-white sm:text-xs">
              {normalizedCategory || "unknown"}
            </span>
          </div>
        </div>

        {/* Right Sidebar - Security Tips */}
        <aside className="flex h-full flex-col gap-4 rounded-3xl border border-gray-200/80 bg-white/90 p-6 shadow-xl shadow-indigo-100/80 backdrop-blur-sm sm:p-7 lg:p-8">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-full bg-linear-to-r from-indigo-500 to-purple-500 text-white shadow-lg shadow-indigo-400/70">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
                Security Tips
              </p>
              <p className="text-sm font-semibold text-slate-900 sm:text-base">
                Stay safe with every email
              </p>
            </div>
          </div>

          <ul className="mt-3 space-y-3 text-sm text-slate-700 sm:text-[15px]">
            <li className="flex gap-3">
              <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-indigo-50 text-indigo-600 shadow-sm">
                <MailWarning className="h-4 w-4" />
              </div>
              <p>
                Always verify the <span className="font-semibold">sender's address</span> and
                domain before clicking links.
              </p>
            </li>
            <li className="flex gap-3">
              <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber-50 text-amber-600 shadow-sm">
                <AlertTriangle className="h-4 w-4" />
              </div>
              <p>
                Be cautious of <span className="font-semibold">urgent requests</span> for passwords,
                money, or sensitive information.
              </p>
            </li>
            <li className="flex gap-3">
              <div className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-emerald-50 text-emerald-600 shadow-sm">
                <span className="text-xs font-bold">IT</span>
              </div>
              <p>
                When in doubt, <span className="font-semibold">forward the email to your IT team</span>{" "}
                for manual review.
              </p>
            </li>
          </ul>
        </aside>
      </div>
    </div>

  );
};

export default ResultCard;
