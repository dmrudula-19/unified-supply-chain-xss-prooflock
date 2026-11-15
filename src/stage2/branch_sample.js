
// TEST 1: Safe reassignment
const userInput = location.search;

let safeData = userInput;
safeData = "Safe content";

document.getElementById("safe").innerHTML = safeData;

// TEST 2: Branch merging
let anotherInput = location.hash;

if (anotherInput) {
    anotherInput = "Safe content";
} else {
    anotherInput = userInput;
}

document.getElementById("output").innerHTML = anotherInput;
