import { useState, useRef, useEffect } from "react";
import FileUpload from "../Components/FileUpload";
import Loader from "../Components/Loader";
import ResultCard from "../Components/ResultCard";

const BACKEND_URL = "http://localhost:5000/analyze_email_route";

function EmailAnalyzer() {
    const [selectedFile, setSelectedFile] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const resultSectionRef = useRef(null);

    const handleAnalyzeClick = async () => {
        if (!selectedFile) return;

        setLoading(true);
        setResult(null);

        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            const res = await fetch(BACKEND_URL, {
                method: "POST",
                body: formData,
            });

            const data = await res.json();
            setResult(data);
        } catch (error) {
            console.error("Analysis failed:", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (result && resultSectionRef.current) {
            resultSectionRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    }, [result]);

    return (
        <div className="flex flex-col gap-12 lg:gap-16">
            {/* Main Upload Section - high visibility */}
            <section
                aria-label="Upload email for phishing analysis"
                className="animate-fadeIn"
            >
                <div className="mx-auto w-full max-w-[1560px] rounded-3xl border-2 border-white bg-white p-8 shadow-2xl shadow-purple-900/30 ring-2 ring-white/50 transition-all duration-300 hover:shadow-purple-900/40 sm:p-10 lg:p-12 lg:min-h-[280px]">
                    <header className="mb-8 space-y-2">
                        <p className="text-xs font-bold uppercase tracking-[0.25em] text-indigo-600 sm:text-sm">
                            Step 1
                        </p>
                        <h2 className="text-2xl font-bold tracking-tight text-slate-900 sm:text-[26px] md:text-[28px]">
                            Upload an email (.eml) to analyze
                        </h2>
                        <p className="max-w-2xl text-base text-slate-600 sm:text-lg">
                            Drag &amp; drop or browse to upload a raw email file. We&apos;ll
                            analyze headers, authentication checks and overall phishing risk.
                        </p>
                    </header>

                    <FileUpload
                        selectedFile={selectedFile}
                        onFileSelect={setSelectedFile}
                        onAnalyze={handleAnalyzeClick}
                        isLoading={loading}
                    />
                </div>
            </section>

            {/* Result Section - scroll target */}
            <section
                ref={resultSectionRef}
                aria-label="Email phishing risk results"
                className="space-y-6 scroll-mt-8"
            >
                {loading && (
                    <div className="mx-auto w-full max-w-[1560px]">
                        <Loader />
                    </div>
                )}

                {result && (
                    <div className="mx-auto w-full max-w-[1560px] rounded-3xl border-2 border-white bg-white p-6 shadow-2xl shadow-purple-900/30 ring-2 ring-white/50 sm:p-8 lg:p-10 lg:min-h-[360px]">
                        <ResultCard result={result} />
                    </div>
                )}
            </section>
        </div>
    );
}

export default EmailAnalyzer;
