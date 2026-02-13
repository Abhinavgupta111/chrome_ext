import React from 'react';

const Loader = ({ message = 'Analyzing email…' }) => {
  return (
    <div className="mt-6 flex flex-col items-center gap-3 rounded-3xl border border-white/70 bg-[var(--card-bg)]/95 p-5 text-center shadow-md shadow-indigo-100/70 backdrop-blur">
      <div className="relative flex h-11 w-11 items-center justify-center">
        <span className="relative inline-flex h-8 w-8 animate-spin rounded-full border-2 border-[var(--primary-color)]/70 border-t-transparent" />
      </div>
      <p className="text-sm font-medium text-slate-800">
        {message}
      </p>
      <p className="max-w-xs text-[13px] text-slate-500">
        This might take a moment while the backend parses headers, checks SPF/DKIM
        and runs risk models.
      </p>
    </div>
  );
};

export default Loader;