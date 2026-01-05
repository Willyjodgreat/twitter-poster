# 🐦 Elite Twitter Bot Secure

A production-ready Twitter/X bot with enhanced security features.

## ✨ Features
- ✅ External cookie management
- ✅ Rate limiting (500/day, 60/hour)
- ✅ Database logging (SQLite)
- ✅ Dashboard with statistics
- ✅ API endpoints
- ✅ N8N webhook integration
- ✅ SSL support
- ✅ Proxy rotation support

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/elite-twitter-bot-secure.git
cd elite-twitter-bot-secure

# Install dependencies
npm install

# Install Playwright
npx playwright install chromium --with-deps

# Set up environment
cp .env.example .env
# Edit .env with your settings

# Create cookies.json with your Twitter cookies
# Format: See docs/COOKIES_GUIDE.md

# Start the bot
npm start
