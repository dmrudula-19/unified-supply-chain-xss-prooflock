// src/engine/patch_generator.js

/**
 * Generates secure code mutations based on the detected vulnerability sink or vector.
 */
function generateRemediationPatch(vulnerabilityType, unsafeSnippet) {
    let patchedCode = "";
    let explanation = "";

    switch (vulnerabilityType) {
        case "DOM_REFLECTED_SINK":
            patchedCode = unsafeSnippet.replace(
                /innerHTML\s*=\s*(.*);/,
                'textContent = $1; // Patched: Use textContent to prevent script execution'
            );
            explanation = "Replaced unsafe `innerHTML` assignment with `textContent` to ensure user input is treated as plain text rather than executable markup.";
            break;

        case "SCRIPT_INJECT_VECTOR":
            patchedCode = `DOMPurify.sanitize(${unsafeSnippet})` ;
            explanation = "Wrapped input in a strict HTML sanitizer (DOMPurify) to strip out malicious script tags and event handlers before rendering.";
            break;

        case "UNSANITIZED_ATTRIBUTE":
            patchedCode = unsafeSnippet.replace(
                /on\w+\s*=\s*["'].*?["']/,
                ''
            );
            explanation = "Removed dangerous inline event handler attributes (e.g., `onerror`, `onload`) from the DOM element.";
            break;

        default:
            patchedCode = `// Apply strict input validation and encoding\nconst safeInput = encodeURIComponent(${unsafeSnippet});`;
            explanation = "Applied general encoding and strict boundary validation.";
    }

    return {
        vulnerability: vulnerabilityType,
        original: unsafeSnippet,
        patch: patchedCode,
        recommendation: explanation,
        timestamp: new Date().toISOString()
    };
}

module.exports = { generateRemediationPatch };
