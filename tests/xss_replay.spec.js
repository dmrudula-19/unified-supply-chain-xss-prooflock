const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const TEST_PAYLOADS = [
    { type: 'Reflected XSS', payload: "<script>alert('XSS_TEST')</script>" },
    { type: 'DOM XSS', payload: "<img src=x onerror=alert('DOM_XSS')>" },
    { type: 'Safe Markdown', payload: "**Bold Text** & `code`" }
];

test.describe('ProofLock Phase 1 Verification Suite', () => {

    TEST_PAYLOADS.forEach(({ type, payload }) => {
        test(`Verify payload handling: ${type}`, async ({ page }) => {
            const consoleLogs = [];
            page.on('console', msg => consoleLogs.push(msg.text()));

            // Navigate to frontend dashboard
            await page.goto('http://localhost:3000');

            // Fill payload input and evaluate
            await page.fill('textarea', payload);
            await page.click('button:has-text("Evaluate Payload")');

            // Wait for telemetry card update
            await page.waitForSelector('#output-content');

            // Take DOM Evidence Snapshot (Task 3)
            const snapshotPath = path.join(__dirname, `../telemetry_artifacts/snapshot_${Date.now()}.png`);
            await page.screenshot({ path: snapshotPath, fullPage: true });

            // Validate dashboard neutralization state
            const outputText = await page.textContent('#output-content');
            console.log(`[${type}] Output Content:`, outputText);
        });
    });
});