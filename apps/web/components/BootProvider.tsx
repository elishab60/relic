"use client";

import React, { createContext, useContext, useState, useEffect } from 'react';

interface BootContextType {
    hasBooted: boolean;
    setHasBooted: (value: boolean) => void;
}

const BootContext = createContext<BootContextType>({
    hasBooted: false,
    setHasBooted: () => { },
});

export function useBootContext() {
    return useContext(BootContext);
}

export default function BootProvider({ children }: { children: React.ReactNode }) {
    const [hasBooted, setHasBooted] = useState(false);
    const [isClient, setIsClient] = useState(false);

    useEffect(() => {
        setIsClient(true);
        // Check sessionStorage on mount
        const bootSeen = sessionStorage.getItem('boot_seen');
        if (bootSeen === 'true') {
            setHasBooted(true);
        }
    }, []);

    const handleSetHasBooted = (value: boolean) => {
        setHasBooted(value);
        if (value) {
            sessionStorage.setItem('boot_seen', 'true');
        }
    };

    // Don't render children until we've checked sessionStorage
    if (!isClient) {
        return null;
    }

    return (
        <BootContext.Provider value={{ hasBooted, setHasBooted: handleSetHasBooted }}>
            {children}
        </BootContext.Provider>
    );
}
