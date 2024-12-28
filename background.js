// Configuration
const CONFIG = {
    SAFE_BROWSING_API_KEY: 'AIzaSyB6ZjzqtDIbH857nRboO2t8p0_qZIw9xi4',
    URLHAUS_API: 'https://urlhaus-api.abuse.ch/v1/url/',
    GITHUB_URLS: [
        'https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt',
        'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt',
        'https://raw.githubusercontent.com/laggis/Dns/main/flagged_urls.json'
    ]
};

// Safe domains that should never be blocked
const SAFE_DOMAINS = new Set([
    'github.com',
    'raw.githubusercontent.com',
    'gitlab.com',
    'githubusercontent.com'
]);

// Default list of known malicious domains
const defaultBlockedDomains = [
    'malware.com',
    'phishing.com',
    'scam.com'
];

// Cache for API results
const safetyCache = new Map();
const urlhausCache = new Map();
const CACHE_DURATION = 3600000; // 1 hour in milliseconds

// Set badge text and color when extension loads
chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
chrome.action.setBadgeText({ text: 'LB' });

// Initialize storage
async function initializeStorage() {
    try {
        const result = await chrome.storage.local.get('blockedUrls');
        if (!result.blockedUrls) {
            // Initialize with default domains, ensuring safe domains are not included
            const initialBlocklist = defaultBlockedDomains.filter(domain => !SAFE_DOMAINS.has(domain));
            await chrome.storage.local.set({ blockedUrls: initialBlocklist });
        } else {
            // Clean existing blocklist
            const cleanedBlocklist = result.blockedUrls.filter(domain => !SAFE_DOMAINS.has(cleanUrl(domain)));
            if (cleanedBlocklist.length !== result.blockedUrls.length) {
                await chrome.storage.local.set({ blockedUrls: cleanedBlocklist });
            }
        }
    } catch (error) {
        console.error('Failed to initialize storage:', error);
    }
}

// Function to clean URL
function cleanUrl(url) {
    try {
        // Remove protocol
        url = url.replace(/^https?:\/\//, '');
        // Remove paths, query parameters, and hashes
        url = url.split('/')[0].split('?')[0].split('#')[0];
        // Remove www and any other common subdomains
        url = url.replace(/^(www\.|ww\.|w\.|m\.)/, '');
        // Remove trailing dots and spaces
        url = url.trim().replace(/\.+$/, '');
        return url.toLowerCase();
    } catch (error) {
        console.error('Error cleaning URL:', error);
        return '';
    }
}

// Update blocklist from GitHub
async function updateBlocklistFromGitHub() {
    try {
        const blockedUrls = new Set();
        console.log('Starting GitHub blocklist update...');
        
        // Fetch and parse each blocklist
        for (const url of CONFIG.GITHUB_URLS) {
            try {
                console.log(`Fetching blocklist from: ${url}`);
                const response = await fetch(url);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const text = await response.text();
                
                // Parse different formats (JSON, text, hosts file)
                if (url.endsWith('.json')) {
                    const json = JSON.parse(text);
                    if (json.urls && Array.isArray(json.urls)) {
                        console.log(`Found ${json.urls.length} URLs in JSON file`);
                        json.urls.forEach(u => {
                            const cleanedUrl = cleanUrl(u);
                            if (cleanedUrl && !SAFE_DOMAINS.has(cleanedUrl)) {
                                blockedUrls.add(cleanedUrl);
                            }
                        });
                    }
                } else {
                    // Parse line by line for text/hosts files
                    const lines = text.split('\n')
                        .map(line => line.trim())
                        .filter(line => line && !line.startsWith('#'));
                    
                    console.log(`Found ${lines.length} lines in text file`);
                    lines.forEach(line => {
                        // Match domain in hosts file format or URL format
                        const match = line.match(/(?:^(?:\d{1,3}\.){3}\d{1,3}\s+([^\s]+)|^([a-z0-9][a-z0-9.-]*\.[a-z]{2,})$)/i);
                        if (match) {
                            const domain = match[1] || match[2];
                            const cleanedUrl = cleanUrl(domain);
                            if (cleanedUrl && !SAFE_DOMAINS.has(cleanedUrl)) {
                                blockedUrls.add(cleanedUrl);
                            }
                        }
                    });
                }
            } catch (error) {
                console.error(`Error fetching blocklist ${url}:`, error);
            }
        }
        
        // Log statistics
        console.log('Blocked URLs before safe domain filter:', blockedUrls.size);
        
        // Convert to array and apply final safety check
        const blockedUrlsArray = Array.from(blockedUrls);
        const finalBlocklist = blockedUrlsArray.filter(url => !SAFE_DOMAINS.has(url));
        
        console.log('Blocked URLs after safe domain filter:', finalBlocklist.length);
        
        // Store updated blocklist
        await chrome.storage.local.set({ 
            blockedUrls: finalBlocklist,
            lastUpdate: Date.now()
        });
        
        console.log('Successfully updated blocklist from GitHub');
    } catch (error) {
        console.error('Failed to update from GitHub:', error);
    }
}

// Helper function to delay execution
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

// Set badge text and color when extension loads
chrome.action.setBadgeBackgroundColor({ color: '#dc2626' });
chrome.action.setBadgeText({ text: 'LB' });

// Initialize storage and update blocklist
chrome.runtime.onInstalled.addListener(async () => {
    console.log('Extension installed/updated');
    await initializeStorage();
    await updateBlocklistFromGitHub();
    setInterval(updateBlocklistFromGitHub, 24 * 60 * 60 * 1000); // Update daily
});

// Also update when extension starts
chrome.runtime.onStartup.addListener(async () => {
    console.log('Extension started');
    await updateBlocklistFromGitHub();
});

// Check URL with Safe Browsing API
async function checkUrlWithSafeBrowsing(url) {
  // Check cache first
  if (safetyCache.has(url)) {
    const cached = safetyCache.get(url);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      return cached.isSafe;
    }
    safetyCache.delete(url);
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.SAFE_BROWSING_API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client: {
          clientId: 'link-blocker-extension',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url }]
        }
      })
    });

    const data = await response.json();
    const isSafe = !data.matches || data.matches.length === 0;
    
    // Cache the result
    safetyCache.set(url, {
      isSafe,
      timestamp: Date.now()
    });
    
    return isSafe;
  } catch (error) {
    console.error('Safe Browsing API error:', error);
    return true; // Fail open if API check fails
  }
}

// Check URL with URLhaus API
async function checkUrlWithUrlhaus(url) {
  // Check cache first
  if (urlhausCache.has(url)) {
    const cached = urlhausCache.get(url);
    if (Date.now() - cached.timestamp < CACHE_DURATION) {
      return cached.isBlocked;
    }
    urlhausCache.delete(url);
  }

  try {
    const response = await fetch(CONFIG.URLHAUS_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });
    const data = await response.json();
    const isBlocked = data.query_status === "ok" && data.threat !== null;
    
    // Cache the result
    urlhausCache.set(url, {
      isBlocked,
      timestamp: Date.now()
    });
    
    return isBlocked;
  } catch (error) {
    console.error('URLhaus API error:', error);
    return false; // Fail open if API check fails
  }
}

// Listen for web navigation events
chrome.webNavigation.onBeforeNavigate.addListener(async function(details) {
  if (details.frameId === 0) { // Only check main frame navigation
    try {
      const url = new URL(details.url);
      const hostname = cleanUrl(url.hostname);
      
      console.log('Checking URL:', hostname); // Debug log
      
      // Get blocked URLs from local storage
      const result = await chrome.storage.local.get('blockedUrls');
      const blockedUrls = result.blockedUrls || [];
      
      console.log('Blocked URLs:', blockedUrls); // Debug log
      
      // More precise URL matching
      const isLocallyBlocked = blockedUrls.some(blockedUrl => {
        const cleanBlockedUrl = cleanUrl(blockedUrl);
        const isBlocked = hostname === cleanBlockedUrl || hostname.endsWith('.' + cleanBlockedUrl);
        if (isBlocked) {
          console.log('URL blocked by local list:', cleanBlockedUrl); // Debug log
        }
        return isBlocked;
      });

      // Check with both APIs in parallel
      console.log('Checking APIs...'); // Debug log
      const [isSafe, isUrlhausSafe] = await Promise.all([
        checkUrlWithSafeBrowsing(details.url),
        checkUrlWithUrlhaus(details.url).then(isBlocked => !isBlocked)
      ]);
      
      console.log('API Results - Safe Browsing:', isSafe, 'URLhaus:', isUrlhausSafe); // Debug log

      if (isLocallyBlocked || !isSafe || !isUrlhausSafe) {
        let reason = isLocallyBlocked ? 'Matched local blocklist' :
                    !isSafe ? 'Flagged by Google Safe Browsing' :
                    'Flagged by URLhaus';

        console.log('Blocking reason:', reason); // Debug log

        // Get extension URL for warning page
        const warningUrl = chrome.runtime.getURL('warning.html') +
          `?url=${encodeURIComponent(details.url)}` +
          `&reason=${encodeURIComponent(reason)}`;
        
        // Redirect to warning page
        chrome.tabs.update(details.tabId, { url: warningUrl });
      } else {
        console.log('URL is safe'); // Debug log
      }
    } catch (error) {
      console.error('Error checking URL:', error);
    }
  }
});
