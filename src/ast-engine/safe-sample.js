// Safe test using textContent instead of innerHTML
const userInput = document.getElementById('search').value;
const safeDiv = document.createElement('div');
safeDiv.textContent = userInput; // Safe sink
document.body.appendChild(safeDiv);