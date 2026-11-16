// Truly clean test with no taint or sinks
const safeMessage = "Welcome user";
document.getElementById("greeting").textContent = safeMessage;