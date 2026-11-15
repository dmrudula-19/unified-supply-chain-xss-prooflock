
const userInput = location.search;

function vulnerableFunction(data) {
    document.getElementById("output").innerHTML = data;
}

function processData(value) {
    vulnerableFunction(value);
}

// Application entry point
function main() {
    processData(userInput);
}

main();

function unusedVulnerableFunction() {
    document.getElementById("output").innerHTML = userInput;
}

