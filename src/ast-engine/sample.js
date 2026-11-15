const userInput = location.search;

document.getElementById("output").innerHTML = userInput;

eval(userInput);