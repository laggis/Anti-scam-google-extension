# Link Blocker Chrome Extension

A powerful Chrome extension that protects users from malicious and unwanted links using multiple trusted blocklists.

## Features

- Blocks malicious URLs using Google Safe Browsing API
- Incorporates multiple trusted blocklists:
  - uBlock Origin's badware and resource abuse lists
  - BlockListProject's fraud lists
  - NoTrack malware list
  - Hexxium Creations threat list
  - Scam Blocklist
  - And more...
- Real-time URL checking
- Custom URL blocking
- User-friendly warning page
- Lightweight and efficient

## Installation

1. Clone this repository or download the ZIP
2. Open Chrome and go to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the extension directory

## Configuration

1. Get a Google Safe Browsing API key from the Google Cloud Console
2. Add your API key to `config.js`

## Usage

- Click the extension icon to add custom URLs to block
- When accessing a blocked URL, you'll see a warning page
- Click "Return to Safety" to go back to the previous page

## Credits

This extension uses blocklists from various trusted sources:
- uBlock Origin
- BlockListProject
- NoTrack
- Hexxium Creations
- DurableNapkin's ScamBlocklist
- And more...

## License

MIT License
