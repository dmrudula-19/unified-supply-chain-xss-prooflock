// Testing a different dangerous XSS sink
const payload = new URLSearchParams(window.location.search).get('q');
eval(payload); // Dangerous execution sink