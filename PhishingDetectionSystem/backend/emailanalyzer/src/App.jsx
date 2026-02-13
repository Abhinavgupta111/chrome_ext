import React from "react";
import Header from "./Components/Header.jsx";
import EmailAnalyzer from "./Pages/EmailAnalyzer.jsx";
import CyberBackground from "./Components/CyberBackground.jsx";

const App = () => {
  return (
    <CyberBackground>
      <div className="flex min-h-screen flex-col">
        {/* Header section */}
        <Header />

        {/* Main content (upload + results) */}
        <main className="flex-1">
          <div className="mx-auto flex w-full max-w-[1560px] flex-col px-4 py-8 sm:px-6 lg:px-10 xl:px-12">
            <EmailAnalyzer />
          </div>
        </main>

        {/* Footer section - light gray contrast to dark page */}
        <footer className="bg-slate-100/95 py-5 text-slate-600 sm:py-6">
          <div className="mx-auto flex w-full max-w-[1560px] flex-col items-center justify-between gap-3 px-4 sm:flex-row sm:px-6 lg:px-10 xl:px-12">
            <p className="text-sm font-semibold tracking-tight sm:text-base">
              Email Phishing Analyzer
            </p>
            <p className="text-xs sm:text-sm">
              For demo use only – always verify suspicious emails with your IT
              team.
            </p>
          </div>
        </footer>
      </div>
    </CyberBackground>
  );
};

export default App;
