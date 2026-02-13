import React from "react";

const Header = () => {
  return (
    <header className="sticky top-0 z-40 w-full bg-purple-900/80 backdrop-blur-sm shadow-[0_2px_12px_rgba(0,0,0,0.15)]">
      <div className="mx-auto flex min-h-[88px] w-full max-w-[1560px] items-center justify-between gap-6 px-4 py-4 sm:px-6 lg:px-10 xl:px-12">
        {/* Logo / App name */}
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-purple-600 text-base font-semibold text-white shadow-lg shadow-purple-900/40">
            SA
          </div>
          <div className="flex flex-col">
            <span className="text-xs font-semibold uppercase tracking-[0.2em] text-slate-300 sm:text-sm">
              Email Security
            </span>
            <h1 className="text-xl font-bold tracking-tight text-white sm:text-2xl md:text-[26px]">
              Email Phishing Analyzer
            </h1>
          </div>
        </div>

        {/* Nav links */}
        <nav className="hidden items-center gap-8 text-[15px] font-medium text-slate-200 sm:flex">
          <button className="transition-colors hover:text-white">
            Dashboard
          </button>
          <button className="transition-colors hover:text-white">
            Security Tips
          </button>
          <button className="transition-colors hover:text-white">
            Help
          </button>
        </nav>

        {/* Compact menu for mobile */}
        <button
          className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-white/30 bg-white/10 text-slate-200 sm:hidden"
          aria-label="Open navigation"
        >
          ☰
        </button>
      </div>
    </header>
  );
};

export default Header;
