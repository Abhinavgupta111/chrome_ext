import React from 'react';

const CyberBackground = ({ children }) => {
    // Outlined hexagon SVG for subtle geometric pattern (cyber aesthetic)
    const hexOutline = `url("data:image/svg+xml,%3Csvg width='100' height='86' viewBox='0 0 100 86' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M50 0L93.3013 21.5V64.5L50 86L6.69873 64.5V21.5L50 0Z' stroke='white' stroke-width='0.5' fill='none' opacity='0.15'/%3E%3C/svg%3E")`;
    return (
        <div className="min-h-screen w-full text-white overflow-auto">
            {/* 1. Deep purple to light lavender vertical gradient (full page) */}
            <div
                className="fixed inset-0 z-0 pointer-events-none"
                style={{
                    background: 'linear-gradient(to bottom, #2d1b4e 0%, #4a3f7a 40%, #8b7eb8 70%, #e8e4f3 100%)',
                }}
            />

            {/* 2. Subtle hexagonal geometric pattern (outlined hexagons) */}
            <div
                className="fixed inset-0 z-0 pointer-events-none opacity-80"
                style={{
                    backgroundImage: hexOutline,
                    backgroundSize: '180px 155px',
                    backgroundPosition: 'center',
                }}
            />

            {/* 3. Content Wrapper */}
            <div className="relative z-10 w-full min-h-screen">
                {children}
            </div>
        </div>
    );
};

export default CyberBackground;
