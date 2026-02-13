import React, { useState } from 'react';
import { UploadCloud } from 'lucide-react';

const FileUpload = ({
  selectedFile,
  onFileSelect,
  onAnalyze,
  isLoading,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [localError, setLocalError] = useState('');

  const handleFiles = files => {
    const file = files?.[0];
    if (!file) return;

    const isEml =
      file.name.toLowerCase().endsWith('.eml') ||
      file.type === 'message/rfc822';

    if (!isEml) {
      setLocalError('Only .eml email files are allowed.');
      onFileSelect(null);
      return;
    }

    setLocalError('');
    onFileSelect(file);
  };

  const handleDrop = event => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragging(false);
    if (event.dataTransfer?.files?.length) {
      handleFiles(event.dataTransfer.files);
    }
  };

  const handleDragOver = event => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = event => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragging(false);
  };

  const handleInputChange = event => {
    const files = event.target.files;
    handleFiles(files);
  };

  const disabled = !selectedFile || isLoading;

  return (
    <section className="space-y-4">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`group relative flex min-h-[260px] cursor-pointer flex-col items-center justify-center rounded-3xl border-2 border-dashed p-8 text-center transition-all duration-300 hover:-translate-y-1 hover:scale-[1.01] sm:p-10 lg:min-h-[300px] lg:p-12 ${
          isDragging
            ? 'border-indigo-500 bg-indigo-50/80 shadow-inner'
            : 'border-slate-300 bg-slate-50/90 hover:border-indigo-400 hover:bg-indigo-50/50 shadow-md'
        }`}
      >

        <input
          type="file"
          accept=".eml"
          onChange={handleInputChange}
          className="absolute inset-0 z-10 h-full w-full cursor-pointer opacity-0"
        />

        <div className="relative z-20 flex flex-col items-center gap-4">
          <div className="flex h-16 w-16 items-center justify-center rounded-full bg-gradient-to-r from-indigo-500 to-purple-500 text-white shadow-lg shadow-indigo-400/70 ring-4 ring-white/70">
            <UploadCloud className="h-8 w-8" />
          </div>

          <div>
            <p className="text-xl font-bold text-slate-800 sm:text-2xl">
              Drag &amp; drop your <span className="text-indigo-600">.eml</span>{' '}
              file here
            </p>
            <p className="mt-2 text-sm text-slate-600 sm:text-base">
              Or click to browse. We only accept raw email files (.eml).
            </p>
          </div>

          <div className="mt-4 inline-flex items-center gap-2 rounded-full bg-slate-50 px-3 py-1.5 text-[11px] font-medium text-slate-600 shadow-sm shadow-slate-200/80">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            <span>
              Selected:{' '}
              {selectedFile ? (
                <span className="font-semibold text-slate-800">
                  {selectedFile.name}
                </span>
              ) : (
                <span className="italic text-slate-400">
                  No file yet
                </span>
              )}
            </span>
          </div>
        </div>
      </div>

      {localError && (
        <p className="text-sm font-medium text-red-500">
          {localError}
        </p>
      )}

      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="text-sm text-slate-600 sm:text-[15px]">
          Make sure your email analysis server is running before you click
          <span className="font-semibold text-slate-800"> Analyze Email</span>.
        </p>

        <button
          type="button"
          onClick={onAnalyze}
          disabled={disabled}
          className={`inline-flex w-full items-center justify-center gap-2 rounded-full px-10 py-4.5 text-base font-semibold tracking-tight shadow-lg transition-all duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--primary-color)] focus-visible:ring-offset-2 focus-visible:ring-offset-slate-50 sm:w-auto sm:px-12 sm:text-lg lg:px-14 lg:py-5 ${
            disabled
              ? 'cursor-not-allowed bg-slate-300 text-slate-600 shadow-none'
              : 'bg-gradient-to-r from-indigo-600 to-purple-600 text-white shadow-indigo-400/80 hover:-translate-y-0.5 hover:scale-[1.02] hover:shadow-2xl active:scale-[0.98]'
          }`}
        >
          {isLoading && (
            <span className="inline-flex h-4 w-4 items-center justify-center">
              <span className="h-3 w-3 animate-spin rounded-full border-2 border-white/60 border-t-transparent" />
            </span>
          )}
          <span>{isLoading ? 'Analyzing…' : 'Analyze Email'}</span>
        </button>
      </div>
    </section>
  );
};

export default FileUpload;