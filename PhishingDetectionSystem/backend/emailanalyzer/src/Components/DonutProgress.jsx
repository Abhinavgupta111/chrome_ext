import React, { useEffect, useState } from 'react';

const DonutProgress = ({ score = 0 }) => {
  const normalized = Math.max(0, Math.min(100, Number(score) || 0));
  const radius = 58;
  const strokeWidth = 9;
  const circumference = 2 * Math.PI * radius;

  const [offset, setOffset] = useState(circumference);

  useEffect(() => {
    const progressOffset =
      circumference - (normalized / 100) * circumference;
    // Small timeout to trigger CSS transition on mount/change
    const id = setTimeout(() => {
      setOffset(progressOffset);
    }, 10);
    return () => clearTimeout(id);
  }, [normalized, circumference]);

  const getColorClasses = value => {
    if (value < 40) {
      return {
        ring: 'text-emerald-400',
        dot: 'bg-emerald-400',
      };
    }
    if (value < 70) {
      return {
        ring: 'text-amber-400',
        dot: 'bg-amber-400',
      };
    }
    return {
      ring: 'text-rose-500',
      dot: 'bg-rose-500',
    };
  };

  const colors = getColorClasses(normalized);

  return (
    <div className="relative flex h-44 w-44 items-center justify-center">
      <svg
        className="h-full w-full -rotate-90 text-slate-200"
        viewBox="0 0 140 140"
      >
        <circle
          className="transition-all duration-500"
          stroke="currentColor"
          strokeWidth={strokeWidth}
          fill="transparent"
          r={radius}
          cx="70"
          cy="70"
        />
        <circle
          className={`transition-all duration-800 ease-out ${colors.ring}`}
          stroke="currentColor"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          fill="transparent"
          r={radius}
          cx="70"
          cy="70"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
        />
      </svg>

      <div className="pointer-events-none absolute inset-6 flex flex-col items-center justify-center rounded-full bg-white text-center shadow-inner shadow-slate-200/90">
        <div className="relative inline-flex flex-col items-center gap-0">
          <span className="text-4xl font-bold tabular-nums text-slate-800 sm:text-5xl">
            {Math.round(normalized)}%
          </span>
          <span className="text-xs font-semibold uppercase tracking-[0.24em] text-slate-500">
            RISK
          </span>
          <span
            className={`absolute -right-1 -top-0.5 h-2.5 w-2.5 rounded-full ${colors.dot} shadow-sm shadow-slate-900/30`}
          />
        </div>
      </div>

    </div>
  );
};

export default DonutProgress;