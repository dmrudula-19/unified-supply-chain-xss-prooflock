
const userInput = location.search;

function displayData(data) {
    document.getElementById("output").innerHTML = data;
}

displayData(userInput);
