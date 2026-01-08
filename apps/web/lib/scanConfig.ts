/**
 * Scan Configuration Helper Module (PR-02b, PR-03 Port Scan Profiles)
 * 
 * Provides utilities for managing scan configuration:
 * - localStorage persistence
 * - Profile normalization
 * - Label mapping
 */

// =============================================================================
// TYPES
// =============================================================================

export type PathProfile = "minimal" | "standard" | "thorough";
export type PortScanProfile = "light" | "mid" | "high";

export interface ScanConfig {
    path_profile: PathProfile;
    port_scan_profile: PortScanProfile;
}

// Valid profile values for validation
const VALID_PATH_PROFILES: PathProfile[] = ["minimal", "standard", "thorough"];
const VALID_PORT_SCAN_PROFILES: PortScanProfile[] = ["light", "mid", "high"];

// Default configuration
const DEFAULT_CONFIG: ScanConfig = {
    path_profile: "standard",
    port_scan_profile: "light"
};

// localStorage key
const STORAGE_KEY = "relic.scanConfig";

// =============================================================================
// PATH PROFILE UTILITIES
// =============================================================================

/**
 * Normalize a path profile value to ensure it's valid.
 * Returns "standard" for invalid or missing values.
 */
export function normalizePathProfile(value: unknown): PathProfile {
    if (typeof value === "string" && VALID_PATH_PROFILES.includes(value as PathProfile)) {
        return value as PathProfile;
    }
    return "standard";
}

/**
 * Get human-readable label for a path profile.
 * 
 * Mapping:
 * - minimal  -> "Low"
 * - standard -> "Balanced"
 * - thorough -> "High"
 */
export function labelFromProfile(profile: PathProfile): string {
    switch (profile) {
        case "minimal":
            return "Low";
        case "standard":
            return "Balanced";
        case "thorough":
            return "High";
        default:
            return "Balanced";
    }
}

/**
 * Get path profile from human-readable label.
 * 
 * Mapping:
 * - "Low"      -> minimal
 * - "Balanced" -> standard
 * - "High"     -> thorough
 */
export function profileFromLabel(label: string): PathProfile {
    switch (label) {
        case "Low":
            return "minimal";
        case "Balanced":
            return "standard";
        case "High":
            return "thorough";
        default:
            return "standard";
    }
}

/**
 * Get description for a path profile.
 */
export function getProfileDescription(profile: PathProfile): string {
    switch (profile) {
        case "minimal":
            return "Fastest scan, fewer endpoints probed (~13 paths)";
        case "standard":
            return "Balanced coverage and speed (~50 paths)";
        case "thorough":
            return "Deep discovery, more requests (~115 paths)";
        default:
            return "Default scan configuration";
    }
}

// =============================================================================
// PORT SCAN PROFILE UTILITIES
// =============================================================================

/**
 * Normalize a port scan profile value to ensure it's valid.
 * Returns "light" for invalid or missing values.
 */
export function normalizePortScanProfile(value: unknown): PortScanProfile {
    if (typeof value === "string" && VALID_PORT_SCAN_PROFILES.includes(value as PortScanProfile)) {
        return value as PortScanProfile;
    }
    return "light";
}

/**
 * Get human-readable label for a port scan profile.
 */
export function labelFromPortScanProfile(profile: PortScanProfile): string {
    switch (profile) {
        case "light":
            return "Light";
        case "mid":
            return "Balanced";
        case "high":
            return "Comprehensive";
        default:
            return "Light";
    }
}

/**
 * Get port scan profile from human-readable label.
 */
export function portScanProfileFromLabel(label: string): PortScanProfile {
    switch (label) {
        case "Light":
            return "light";
        case "Balanced":
            return "mid";
        case "Comprehensive":
            return "high";
        default:
            return "light";
    }
}

/**
 * Get description for a port scan profile.
 */
export function getPortScanProfileDescription(profile: PortScanProfile): string {
    switch (profile) {
        case "light":
            return "Common service ports only (~12 ports, <5s)";
        case "mid":
            return "Top 100 most common ports (~30s)";
        case "high":
            return "Top 1000 ports, comprehensive scan (2-5min)";
        default:
            return "Default port scan configuration";
    }
}

/**
 * Get statistics for a port scan profile.
 */
export function getPortScanProfileStats(profile: PortScanProfile): {
    ports: number;
    estimatedTime: string;
    impact: "fast" | "medium" | "slow";
    description: string;
} {
    switch (profile) {
        case "light":
            return {
                ports: 12,
                estimatedTime: "< 5 seconds",
                impact: "fast",
                description: "Common services"
            };
        case "mid":
            return {
                ports: 100,
                estimatedTime: "~30 seconds",
                impact: "medium",
                description: "Top 100 ports"
            };
        case "high":
            return {
                ports: 1000,
                estimatedTime: "2-5 minutes",
                impact: "slow",
                description: "Comprehensive"
            };
        default:
            return {
                ports: 12,
                estimatedTime: "< 5 seconds",
                impact: "fast",
                description: "Common services"
            };
    }
}

/**
 * Get badge display info for a port scan profile.
 */
export function getPortScanProfileBadgeInfo(profile: PortScanProfile): {
    label: string;
    colorClass: string;
    icon: "zap" | "shield" | "crosshair";
} {
    switch (profile) {
        case "light":
            return {
                label: "LIGHT",
                colorClass: "bg-terminal-dim/20 text-terminal-dim border-terminal-dim/30",
                icon: "zap"
            };
        case "mid":
            return {
                label: "MID",
                colorClass: "bg-terminal-accent/20 text-terminal-accent border-terminal-accent/30",
                icon: "shield"
            };
        case "high":
            return {
                label: "HIGH",
                colorClass: "bg-amber-500/20 text-amber-400 border-amber-500/30",
                icon: "crosshair"
            };
        default:
            return {
                label: "LIGHT",
                colorClass: "bg-terminal-dim/20 text-terminal-dim border-terminal-dim/30",
                icon: "zap"
            };
    }
}

// =============================================================================
// LOCALSTORAGE PERSISTENCE
// =============================================================================

/**
 * Get stored scan configuration from localStorage.
 * Returns default config if not found or invalid.
 */
export function getStoredScanConfig(): ScanConfig {
    if (typeof window === "undefined") {
        return DEFAULT_CONFIG;
    }

    try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (!stored) {
            return DEFAULT_CONFIG;
        }

        const parsed = JSON.parse(stored);

        // Validate structure
        if (typeof parsed !== "object" || parsed === null) {
            return DEFAULT_CONFIG;
        }

        return {
            path_profile: normalizePathProfile(parsed.path_profile),
            port_scan_profile: normalizePortScanProfile(parsed.port_scan_profile)
        };
    } catch (error) {
        console.warn("Failed to parse stored scan config, using defaults:", error);
        return DEFAULT_CONFIG;
    }
}

/**
 * Store scan configuration to localStorage.
 */
export function setStoredScanConfig(config: ScanConfig): void {
    if (typeof window === "undefined") {
        return;
    }

    try {
        const normalized: ScanConfig = {
            path_profile: normalizePathProfile(config.path_profile),
            port_scan_profile: normalizePortScanProfile(config.port_scan_profile)
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(normalized));
    } catch (error) {
        console.warn("Failed to store scan config:", error);
    }
}

// =============================================================================
// SCAN RESULT HELPERS
// =============================================================================

/**
 * Extract path profile from a scan record.
 * 
 * Priority:
 * 1. config_json?.path_profile (from DB)
 * 2. result_json?.debug_info?.config_used?.path_profile
 * 3. Fallback to "standard"
 */
export function getProfileFromScanRecord(
    configJson?: Record<string, any> | null,
    resultJson?: Record<string, any> | null
): PathProfile {
    // Priority 1: config_json
    if (configJson?.path_profile) {
        return normalizePathProfile(configJson.path_profile);
    }

    // Priority 2: result_json.debug_info.config_used
    if (resultJson?.debug_info?.config_used?.path_profile) {
        return normalizePathProfile(resultJson.debug_info.config_used.path_profile);
    }

    // Fallback
    return "standard";
}

/**
 * Extract port scan profile from a scan record.
 */
export function getPortScanProfileFromScanRecord(
    configJson?: Record<string, any> | null,
    resultJson?: Record<string, any> | null
): PortScanProfile {
    // Priority 1: config_json
    if (configJson?.port_scan_profile) {
        return normalizePortScanProfile(configJson.port_scan_profile);
    }

    // Priority 2: result_json.debug_info.config_used
    if (resultJson?.debug_info?.config_used?.port_scan_profile) {
        return normalizePortScanProfile(resultJson.debug_info.config_used.port_scan_profile);
    }

    // Priority 3: result_json.debug_info.port_scan_summary.profile
    if (resultJson?.debug_info?.port_scan_summary?.profile) {
        return normalizePortScanProfile(resultJson.debug_info.port_scan_summary.profile);
    }

    // Fallback
    return "light";
}

/**
 * Get badge display info for a path profile.
 */
export function getProfileBadgeInfo(profile: PathProfile): {
    label: string;
    colorClass: string;
} {
    switch (profile) {
        case "minimal":
            return {
                label: "MINIMAL",
                colorClass: "bg-terminal-dim/20 text-terminal-dim border-terminal-dim/30"
            };
        case "standard":
            return {
                label: "STANDARD",
                colorClass: "bg-terminal-accent/20 text-terminal-accent border-terminal-accent/30"
            };
        case "thorough":
            return {
                label: "THOROUGH",
                colorClass: "bg-terminal-text/20 text-terminal-textBright border-terminal-text/30"
            };
        default:
            return {
                label: "STANDARD",
                colorClass: "bg-terminal-accent/20 text-terminal-accent border-terminal-accent/30"
            };
    }
}


// =============================================================================
// PROFILE STATISTICS
// =============================================================================

/**
 * Get statistics for a profile (paths checked, max pages discovered).
 */
export function getProfileStats(profile: PathProfile): {
    paths: number;
    maxPages: number;
    description: string;
} {
    switch (profile) {
        case "minimal":
            return {
                paths: 13,
                maxPages: 20,
                description: "Fast scan"
            };
        case "standard":
            return {
                paths: 48,
                maxPages: 50,
                description: "Balanced"
            };
        case "thorough":
            return {
                paths: 98,
                maxPages: 100,
                description: "Deep scan"
            };
        default:
            return {
                paths: 48,
                maxPages: 50,
                description: "Balanced"
            };
    }
}


