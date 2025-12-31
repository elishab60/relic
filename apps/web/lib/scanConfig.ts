/**
 * Scan Configuration Helper Module (PR-02b)
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

export interface ScanConfig {
    path_profile: PathProfile;
}

// Valid profile values for validation
const VALID_PROFILES: PathProfile[] = ["minimal", "standard", "thorough"];

// Default configuration
const DEFAULT_CONFIG: ScanConfig = {
    path_profile: "standard"
};

// localStorage key
const STORAGE_KEY = "relic.scanConfig";

// =============================================================================
// PROFILE UTILITIES
// =============================================================================

/**
 * Normalize a path profile value to ensure it's valid.
 * Returns "standard" for invalid or missing values.
 */
export function normalizePathProfile(value: unknown): PathProfile {
    if (typeof value === "string" && VALID_PROFILES.includes(value as PathProfile)) {
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
            path_profile: normalizePathProfile(parsed.path_profile)
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
            path_profile: normalizePathProfile(config.path_profile)
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

