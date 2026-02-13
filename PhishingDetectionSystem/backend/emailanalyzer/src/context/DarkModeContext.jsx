import React, { createContext, useContext, useEffect, useState } from 'react';

const DarkModeContext = createContext(undefined);

export const DarkModeProvider = ({ children }) => {
  const [isDark, setIsDark] = useState(() => {
    if (typeof window === 'undefined') return false;
    const stored = window.localStorage.getItem('theme');
    if (stored === 'dark') return true;
    if (stored === 'light') return false;
    return (
      window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches
    );
  });

  useEffect(() => {
    if (typeof document === 'undefined') return;
    const root = document.documentElement;

    if (isDark) {
      root.classList.add('dark');
      window.localStorage.setItem('theme', 'dark');
    } else {
      root.classList.remove('dark');
      window.localStorage.setItem('theme', 'light');
    }
  }, [isDark]);

  const toggleDarkMode = () => setIsDark(prev => !prev);

  return (
    <DarkModeContext.Provider value={{ isDark, toggleDarkMode }}>
      {children}
    </DarkModeContext.Provider>
  );
};

export const useDarkMode = () => {
  const ctx = useContext(DarkModeContext);
  if (!ctx) {
    throw new Error('useDarkMode must be used within DarkModeProvider');
  }
  return ctx;
};

