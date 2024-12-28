document.addEventListener('DOMContentLoaded', function() {
  const blockUrlInput = document.getElementById('blockUrl');
  const addUrlButton = document.getElementById('addUrl');
  const blockedList = document.getElementById('blockedList');
  const testApiButton = document.getElementById('testApi');
  const testResults = document.getElementById('testResults');
  const urlhausStatus = document.getElementById('urlhausStatus');
  const urlhausIndicator = document.getElementById('urlhausIndicator');

  // Test URLhaus API with a known malicious URL
  async function testUrlhausApi() {
    const testUrl = 'http://malware.testing.google.test/testing/malware/';
    
    try {
      // Update status to testing
      urlhausStatus.textContent = 'Testing...';
      urlhausIndicator.className = 'status-indicator unknown';
      testResults.style.display = 'none';

      const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(testUrl)}`
      });

      const data = await response.json();
      
      if (response.ok && data.query_status === "ok") {
        urlhausStatus.textContent = 'Working';
        urlhausIndicator.className = 'status-indicator working';
        testResults.textContent = 'URLhaus API is working correctly!';
        testResults.className = 'success';
      } else {
        throw new Error(data.query_status || 'API returned unexpected response');
      }
    } catch (error) {
      urlhausStatus.textContent = 'Error';
      urlhausIndicator.className = 'status-indicator error';
      testResults.textContent = `Error testing URLhaus API: ${error.message}`;
      testResults.className = 'error';
    }
    
    testResults.style.display = 'block';
  }

  // Add URL to blocklist
  async function addUrlToBlocklist() {
    const url = blockUrlInput.value.trim();
    if (!url) return;

    try {
      const result = await chrome.storage.local.get('blockedUrls');
      const blockedUrls = result.blockedUrls || [];
      
      if (!blockedUrls.includes(url)) {
        blockedUrls.push(url);
        await chrome.storage.local.set({ blockedUrls });
        updateBlockedList();
        blockUrlInput.value = '';
      }
    } catch (error) {
      console.error('Error adding URL:', error);
    }
  }

  // Update the displayed list of blocked URLs
  async function updateBlockedList() {
    try {
      const result = await chrome.storage.local.get('blockedUrls');
      const blockedUrls = result.blockedUrls || [];
      
      blockedList.innerHTML = '<h3>Blocked URLs:</h3>';
      
      blockedUrls.forEach(url => {
        const div = document.createElement('div');
        div.className = 'blocked-item';
        
        const urlSpan = document.createElement('span');
        urlSpan.textContent = url;
        
        const removeButton = document.createElement('button');
        removeButton.textContent = 'Remove';
        removeButton.className = 'remove-btn';
        removeButton.onclick = () => removeUrl(url);
        
        div.appendChild(urlSpan);
        div.appendChild(removeButton);
        blockedList.appendChild(div);
      });
    } catch (error) {
      console.error('Error updating list:', error);
    }
  }

  // Remove URL from blocklist
  async function removeUrl(url) {
    try {
      const result = await chrome.storage.local.get('blockedUrls');
      const blockedUrls = result.blockedUrls || [];
      const updatedUrls = blockedUrls.filter(u => u !== url);
      await chrome.storage.local.set({ blockedUrls: updatedUrls });
      updateBlockedList();
    } catch (error) {
      console.error('Error removing URL:', error);
    }
  }

  // Event listeners
  addUrlButton.addEventListener('click', addUrlToBlocklist);
  testApiButton.addEventListener('click', testUrlhausApi);
  blockUrlInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') addUrlToBlocklist();
  });

  // Initialize
  updateBlockedList();
});
