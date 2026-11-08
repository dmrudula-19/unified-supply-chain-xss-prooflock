// src/engine/dependency_analyzer.js
const fs = require('fs');
const path = require('path');

/**
 * Parses package.json and evaluates dependencies for supply-chain risks.
 */
function analyzeManifest(packageJsonPath) {
    if (!fs.existsSync(packageJsonPath)) {
        return { error: "package.json not found." };
    }

    const rawData = fs.readFileSync(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(rawData);

    const dependencies = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {})
    };

    const auditResults = [];

    for (const [name, version] of Object.entries(dependencies)) {
        let riskScore = "LOW";
        let flags = [];

        // Check for wildcard or loose versioning risks
        if (version.includes('*') || version.includes('x') || version.startsWith('>')) {
            riskScore = "MEDIUM";
            flags.push("Loose or floating version range detected");
        }

        // Check for git URLs or local paths (supply-chain vector)
        if (version.startsWith('git+') || version.startsWith('http://') || version.startsWith('file:')) {
            riskScore = "HIGH";
            flags.push("Non-registry dependency source (external URL/file)");
        }

        auditResults.push({
            package: name,
            version: version,
            risk: riskScore,
            flags: flags
        });
    }

    return {
        projectName: pkg.name || "unnamed-project",
        totalDependencies: Object.keys(dependencies).length,
        auditTimestamp: new Date().toISOString(),
        findings: auditResults
    };
}

module.exports = { analyzeManifest };