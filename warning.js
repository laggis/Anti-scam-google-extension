// Get URL parameters
const params = new URLSearchParams(window.location.search);
document.getElementById('blockedUrl').textContent = params.get('url') || 'Unknown URL';
document.getElementById('blockReason').textContent = params.get('reason') || 'Matched blocklist';
