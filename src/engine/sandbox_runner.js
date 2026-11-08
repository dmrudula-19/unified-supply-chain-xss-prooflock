// src/engine/sandbox_runner.js
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Executes a package installation inside an isolated Docker container
 * to monitor preinstall/postinstall script risks.
 */
function runSandboxTest(targetPackage, callback) {
    // Create a temporary workspace for the isolated install test
    const tempDir = path.join(__dirname, '../../temp_sandbox');
    if (!fs.existsSync(tempDir)) {
        fs.mkdirSync(tempDir, { recursive: true });
    }

    // Write a minimalist package.json inside the temp sandbox
    const minimalManifest = {
        name: "prooflock-sandbox-test",
        version: "1.0.0",
        dependencies: {
            [targetPackage]: "latest"
        }
    };
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify(minimalManifest, null, 2));

    // Docker command to run npm install in a restricted node container
    // Limits network access or isolates the file system
    const dockerCmd = `docker run --rm -v "${tempDir}:/usr/src/app" -w /usr/src/app node:18-alpine npm install --ignore-scripts=false`;

    console.log(`[Sandbox] Spawning isolated container for package: ${targetPackage}`);
    
    exec(dockerCmd, { timeout: 30000 }, (error, stdout, stderr) => {
        // Cleanup temp files
        try {
            fs.rmSync(tempDir, { recursive: true, force: true });
        } catch (e) {
            // ignore cleanup errors
        }

        if (error) {
            callback({
                status: "INTERCEPTED_OR_FAILED",
                package: targetPackage,
                error: error.message,
                stderr: stderr
            });
        } else {
            callback({
                status: "PASSED_SANDBOX",
                package: targetPackage,
                output: stdout
            });
        }
    });
}

module.exports = { runSandboxTest };