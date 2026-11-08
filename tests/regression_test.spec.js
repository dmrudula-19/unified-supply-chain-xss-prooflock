const { test, expect } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

test.describe('ProofLock Benign Input Regression Suite', () => {
    const rawData = fs.readFileSync(path.join(__dirname, 'benign_regression.json'), 'utf-8');
    const { regression_cases } = JSON.parse(rawData);

    regression_cases.forEach(({ id, category, input, expected }) => {
        test(`[${id}] Should pass safe input: ${category}`, async ({ page }) => {
            // Send direct request to backend vulnerable-sink API to check status
            const response = await page.request.post('http://localhost:3000/api/vulnerable-sink', {
                data: { payload: input, sourceContext: 'REGRESSION_TEST' }
            });

            const jsonResponse = await response.json();
            
            console.log(`[${id}] Input: "${input}" -> Status: ${jsonResponse.status}`);
            
            // Assert that benign input is NOT blocked (should render safely)
            expect(jsonResponse.status).toBe(expected);
        });
    });
});