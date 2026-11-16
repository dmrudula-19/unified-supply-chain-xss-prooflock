// Sanitized reassignment test
let data = location.search;
data = "Sanitized static string";
document.getElementById("output").innerHTML = data;