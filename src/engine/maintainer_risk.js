// src/engine/maintainer_risk.js

/**
 * Simulates checking npm registry metadata for maintainer and publication risks.
 */
async function checkRegistryMetadata(packageName) {
    // In production, this queries the official npm registry API: https://registry.npmjs.org/{packageName}
    // For our research prototype, we evaluate mock metadata attributes or query live registry data.
    
    try {
        const response = await fetch(`https://registry.npmjs.org/${packageName}`);
        if (!response.ok) {
            return { package: packageName, status: "NOT_FOUND", risk: "UNKNOWN" };
        }
        
        const data = await response.json();
        const timeEntries = data.time || {};
        const versions = Object.keys(data.versions || {});
        const maintainers = data.maintainers || [];

        const createdAt = new Date(timeEntries.created);
        const modifiedAt = new Date(timeEntries.modified);
        const ageInDays = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);

        let riskLevel = "LOW";
        let flags = [];

        // Check for single maintainer risk
        if (maintainers.length <= 1) {
            riskLevel = "MEDIUM";
            flags.push("Single maintainer dependency risk");
        }

        // Check for brand new package anomaly (< 30 days old)
        if (ageInDays < 30) {
            riskLevel = "HIGH";
            flags.push("Newly created package (potential typosquatting vector)");
        }

        return {
            package: packageName,
            totalVersions: versions.length,
            maintainerCount: maintainers.length,
            packageAgeDays: Math.floor(ageInDays),
            risk: riskLevel,
            flags: flags
        };
    } catch (error) {
        return { package: packageName, error: error.message };
    }
}

module.exports = { checkRegistryMetadata };
