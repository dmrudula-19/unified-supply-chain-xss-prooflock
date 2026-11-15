
const userInput = location.search;

function processData(data) {
    return data;
}

function displayData(value) {
    document.getElementById("output").innerHTML = value;
}

displayData(processData(userInput));

