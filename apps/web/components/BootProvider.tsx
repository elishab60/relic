'use client';

import React, { createContext, useContext, useState } from 'react';

interface BootContextType {
    hasBooted: boolean;
    setHasBooted: (value: boolean) => void;
}

const BootContext = createContext<BootContextType | undefined>(undefined);

export function BootProvider({ children }: { children: React.ReactNode }) {
    const [hasBooted, setHasBooted] = useState(false);

    return (
        <BootContext.Provider value={{ hasBooted, setHasBooted }}>
            {children}
        </BootContext.Provider>
    );
}

export function useBoot() {
    const context = useContext(BootContext);
    if (context === undefined) {
        throw new Error('useBoot must be used within a BootProvider');
    }
    return context;
}
