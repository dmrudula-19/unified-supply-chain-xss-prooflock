
const userInput = location.search;

// Test 1: Variable-to-variable propagation
const firstValue = userInput;
const secondValue = firstValue;

document.getElementById("output").innerHTML = secondValue;

// Test 2: outerHTML sink
const anotherValue = userInput;
document.getElementById("box").outerHTML = anotherValue;

// Test 3: eval sink
const scriptInput = userInput;
eval(scriptInput);

// Test 4: document.write sink
const pageContent = userInput;
document.write(pageContent);

// Test 5: Reassignment with safe data
let reassignedValue = location.search;

reassignedValue = "This is safe data";

document.getElementById("safeOutput").innerHTML = reassignedValue;
