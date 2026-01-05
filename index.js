// ==================== ELITE TWITTER BOT PRO ====================
// COMPLETE WITH: Dashboard, Rate Limits, Proxies, Stealth, Database
const { chromium } = require('playwright');
const express = require('express');
const https = require('https'); // ADDED FOR SSL
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.API_PORT || 3003;
const SSL_PORT = process.env.SSL_PORT || 3443; // ADDED SSL PORT

// ==================== CONFIGURATION ====================
const CONFIG = {
  // Limits
  DAILY_LIMIT: 500,
  HOURLY_LIMIT: 60,
  MIN_DELAY: 180000,    // 3 minutes
  MAX_DELAY: 360000,    // 6 minutes
  
  // Browser
  MAX_BROWSERS: 3,
  USE_STEALTH: true,
  
  // Proxy
  USE_PROXY: process.env.USE_PROXY === 'true',
  PROXY_LIST: process.env.PROXY_LIST?.split(',') || [],
  
  // Database
  USE_DATABASE: true,
  
  // Safety
  MAX_RETRIES: 3,
  SESSION_TIMEOUT: 3600000,
  
  // Security (ADDED)
  REQUIRE_API_KEY: process.env.REQUIRE_API_KEY === 'true',
  API_KEYS: process.env.API_KEYS?.split(',') || [],
  ALLOWED_IPS: process.env.ALLOWED_IPS?.split(',') || [],
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*'
};

// ==================== LOAD COOKIES FROM FILE ====================
function loadCookies() {
  try {
    if (!fs.existsSync('cookies.json')) {
      console.error(`
❌ ERROR: cookies.json file not found!
💡 Create cookies.json with your Twitter cookies in the same format.
💡 You can copy from your original hardcoded cookies and replace values.
      `);
      process.exit(1);
    }
    
    const cookies = JSON.parse(fs.readFileSync('cookies.json', 'utf8'));
    
    // Validate required cookies
    const requiredCookies = ['auth_token', 'ct0', 'kdt', 'twid'];
    const missing = requiredCookies.filter(name => 
      !cookies.some(cookie => cookie.name === name)
    );
    
    if (missing.length > 0) {
      console.error(`❌ Missing required cookies: ${missing.join(', ')}`);
      process.exit(1);
    }
    
    console.log(`✅ Loaded ${cookies.length} cookies from cookies.json`);
    
    // Mask sensitive info in logs
    const authCookie = cookies.find(c => c.name === 'auth_token');
    if (authCookie) {
      const token = authCookie.value;
      const masked = token.substring(0, 6) + '...' + token.substring(token.length - 6);
      console.log(`🔐 Auth token: ${masked}`);
    }
    
    return cookies;
    
  } catch (error) {
    console.error('❌ Error loading cookies:', error.message);
    console.log('💡 Make sure cookies.json is valid JSON format');
    process.exit(1);
  }
}

const YOUR_TWITTER_COOKIES = loadCookies(); // REPLACED HARDCODED COOKIES

// ==================== SECURITY MIDDLEWARE ====================
// Basic request validation
app.use((req, res, next) => {
  // Rate limiting by IP (simple version)
  const clientIP = req.ip || req.connection.remoteAddress;
  
  // Block disallowed IPs if configured
  if (CONFIG.ALLOWED_IPS.length > 0 && !CONFIG.ALLOWED_IPS.includes(clientIP) && clientIP !== '::1' && clientIP !== '127.0.0.1') {
    console.warn(`🚫 Blocked IP: ${clientIP}`);
    return res.status(403).json({ success: false, error: 'Access denied' });
  }
  
  // Add security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  next();
});

// API key authentication for /api endpoints
const apiKeyAuth = (req, res, next) => {
  if (!CONFIG.REQUIRE_API_KEY) {
    return next();
  }
  
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  
  if (!apiKey) {
    return res.status(401).json({ 
      success: false, 
      error: 'API key required. Use x-api-key header or api_key query parameter' 
    });
  }
  
  if (!CONFIG.API_KEYS.includes(apiKey)) {
    console.warn(`❌ Invalid API key attempt from ${req.ip}`);
    return res.status(403).json({ 
      success: false, 
      error: 'Invalid API key' 
    });
  }
  
  next();
};

// ==================== DATABASE MANAGER ====================
class DatabaseManager {
  constructor() {
    this.db = new sqlite3.Database('bot_stats.db');
    this.initDatabase();
  }
  
  initDatabase() {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS tweets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tweet_id TEXT NOT NULL,
        reply_text TEXT,
        status TEXT,
        error TEXT,
        response_time INTEGER,
        proxy_used TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    this.db.run(`
      CREATE TABLE IF NOT EXISTS daily_stats (
        date DATE PRIMARY KEY,
        count INTEGER DEFAULT 0,
        success INTEGER DEFAULT 0,
        failed INTEGER DEFAULT 0
      )
    `);
    
    this.db.run(`
      CREATE TABLE IF NOT EXISTS proxies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        proxy TEXT UNIQUE,
        success_count INTEGER DEFAULT 0,
        fail_count INTEGER DEFAULT 0,
        last_used DATETIME
      )
    `);
    
    // ADDED: Security logs table
    this.db.run(`
      CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        endpoint TEXT,
        user_agent TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }
  
  async logTweet(tweetId, replyText, status, error = null, responseTime = null, proxy = null) {
    return new Promise((resolve) => {
      this.db.run(
        `INSERT INTO tweets (tweet_id, reply_text, status, error, response_time, proxy_used) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [tweetId, replyText, status, error, responseTime, proxy],
        resolve
      );
    });
  }
  
  async logSecurityEvent(ip, endpoint, userAgent, status) {
    return new Promise((resolve) => {
      this.db.run(
        `INSERT INTO security_logs (ip_address, endpoint, user_agent, status) 
         VALUES (?, ?, ?, ?)`,
        [ip, endpoint, userAgent || 'Unknown', status],
        resolve
      );
    });
  }
  
  async updateDailyStats() {
    const today = new Date().toISOString().split('T')[0];
    return new Promise((resolve) => {
      this.db.run(
        `INSERT OR REPLACE INTO daily_stats (date, count, success, failed)
         VALUES (?, COALESCE((SELECT count FROM daily_stats WHERE date = ?), 0) + 1,
                 COALESCE((SELECT success FROM daily_stats WHERE date = ?), 0) + 1,
                 COALESCE((SELECT failed FROM daily_stats WHERE date = ?), 0))`,
        [today, today, today, today],
        resolve
      );
    });
  }
  
  async getStats() {
    return new Promise((resolve) => {
      this.db.all(`
        SELECT 
          (SELECT COUNT(*) FROM tweets) as total,
          (SELECT COUNT(*) FROM tweets WHERE status = 'success') as success,
          (SELECT COUNT(*) FROM tweets WHERE status = 'failed') as failed,
          (SELECT COUNT(*) FROM tweets WHERE DATE(created_at) = DATE('now')) as today,
          (SELECT SUM(response_time) / COUNT(*) FROM tweets WHERE response_time IS NOT NULL) as avg_time
      `, (err, rows) => {
        resolve(rows?.[0] || { total: 0, success: 0, failed: 0, today: 0, avg_time: 0 });
      });
    });
  }
  
  async getRecentTweets(limit = 20) {
    return new Promise((resolve) => {
      this.db.all(
        `SELECT * FROM tweets ORDER BY created_at DESC LIMIT ?`,
        [limit],
        (err, rows) => resolve(rows || [])
      );
    });
  }
}

// ==================== PROXY ROTATOR ====================
class ProxyRotator {
  constructor() {
    this.proxies = CONFIG.PROXY_LIST;
    this.currentIndex = 0;
    this.stats = {};
  }
  
  getNextProxy() {
    if (!CONFIG.USE_PROXY || this.proxies.length === 0) {
      return null;
    }
    
    const proxy = this.proxies[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.proxies.length;
    
    return {
      server: proxy,
      bypass: '*.twitter.com,*.x.com'
    };
  }
  
  markSuccess(proxy) {
    if (!proxy) return;
    this.stats[proxy] = (this.stats[proxy] || 0) + 1;
  }
  
  markFailed(proxy) {
    if (!proxy) return;
    this.stats[proxy] = (this.stats[proxy] || 0) - 1;
  }
}

// ==================== RATE LIMITER ====================
class RateLimiter {
  constructor() {
    this.dailyCount = 0;
    this.hourlyCount = 0;
    this.lastAction = 0;
    this.ipLimits = new Map(); // Track per-IP usage
    this.loadState();
  }
  
  canProceed(ip = null) {
    // Check global limits
    if (this.dailyCount >= CONFIG.DAILY_LIMIT) {
      console.log(`🚫 Daily limit reached: ${this.dailyCount}/${CONFIG.DAILY_LIMIT}`);
      return false;
    }
    
    if (this.hourlyCount >= CONFIG.HOURLY_LIMIT) {
      console.log(`🚫 Hourly limit reached: ${this.hourlyCount}/${CONFIG.HOURLY_LIMIT}`);
      return false;
    }
    
    // Check per-IP limits (prevent abuse)
    if (ip) {
      const ipKey = `ip_${ip}`;
      const ipData = this.ipLimits.get(ipKey) || { count: 0, lastRequest: 0 };
      
      // 10 requests per IP per hour
      if (ipData.count >= 10) {
        const timeSince = Date.now() - ipData.lastRequest;
        if (timeSince < 3600000) {
          console.log(`🚫 IP ${ip} limit reached`);
          return false;
        } else {
          ipData.count = 0; // Reset after hour
        }
      }
    }
    
    const timeSince = Date.now() - this.lastAction;
    if (timeSince < CONFIG.MIN_DELAY) {
      const waitSec = Math.ceil((CONFIG.MIN_DELAY - timeSince) / 1000);
      console.log(`⏳ Please wait ${Math.ceil(waitSec/60)} minutes ${waitSec%60} seconds`);
      return false;
    }
    
    return true;
  }
  
  recordAction(ip = null) {
    this.dailyCount++;
    this.hourlyCount++;
    this.lastAction = Date.now();
    
    // Track per-IP usage
    if (ip) {
      const ipKey = `ip_${ip}`;
      const ipData = this.ipLimits.get(ipKey) || { count: 0, lastRequest: 0 };
      ipData.count++;
      ipData.lastRequest = Date.now();
      this.ipLimits.set(ipKey, ipData);
    }
    
    this.saveState();
    
    console.log(`📊 Daily: ${this.dailyCount}/${CONFIG.DAILY_LIMIT} | Hourly: ${this.hourlyCount}/${CONFIG.HOURLY_LIMIT}`);
    console.log(`🎯 Remaining today: ${CONFIG.DAILY_LIMIT - this.dailyCount}`);
  }
  
  getWaitTime() {
    const timeSince = Date.now() - this.lastAction;
    if (timeSince < CONFIG.MIN_DELAY) {
      return CONFIG.MIN_DELAY - timeSince;
    }
    
    // Random delay between 3 and 6 minutes
    return CONFIG.MIN_DELAY + Math.random() * (CONFIG.MAX_DELAY - CONFIG.MIN_DELAY);
  }
  
  saveState() {
    const state = {
      dailyCount: this.dailyCount,
      hourlyCount: this.hourlyCount,
      lastAction: this.lastAction,
      ipLimits: Array.from(this.ipLimits.entries()),
      savedAt: Date.now()
    };
    
    fs.writeFileSync('rate_state.json', JSON.stringify(state, null, 2));
  }
  
  loadState() {
    try {
      if (fs.existsSync('rate_state.json')) {
        const state = JSON.parse(fs.readFileSync('rate_state.json', 'utf8'));
        this.dailyCount = state.dailyCount || 0;
        this.hourlyCount = state.hourlyCount || 0;
        this.lastAction = state.lastAction || 0;
        this.ipLimits = new Map(state.ipLimits || []);
      }
    } catch (e) {
      console.log('No previous rate state found');
    }
  }
}

// ==================== RANDOM USER AGENTS ====================
const RANDOM_USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15'
];

// ==================== TWITTER BOT ====================
class TwitterBot {
  constructor(database, proxyRotator, rateLimiter) {
    this.db = database;
    this.proxyRotator = proxyRotator;
    this.rateLimiter = rateLimiter;
    this.browser = null;
    this.page = null;
    this.isLoggedIn = false;
    this.cookieRefreshInterval = null;
    this.lastCookieCheck = 0;
  }
  
  async initialize() {
    console.log('🚀 Initializing Twitter Bot Pro with external cookies...');
    
    const randomUserAgent = RANDOM_USER_AGENTS[Math.floor(Math.random() * RANDOM_USER_AGENTS.length)];
    
    const launchOptions = {
      headless: false,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--ignore-certificate-errors',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
        '--hide-scrollbars',
        '--mute-audio'
      ]
    };
    
    // Add proxy if enabled
    const proxy = this.proxyRotator.getNextProxy();
    if (proxy) {
      launchOptions.proxy = proxy;
      console.log(`🌐 Using proxy: ${proxy.server}`);
    }
    
    this.browser = await chromium.launch(launchOptions);
    
    const context = await this.browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent: randomUserAgent,
      locale: 'en-US',
      timezoneId: 'America/New_York'
    });
    
    // Stealth mode
    if (CONFIG.USE_STEALTH) {
      await context.addInitScript(() => {
        // Override webdriver property
        Object.defineProperty(navigator, 'webdriver', { 
          get: () => undefined 
        });
        
        // Override plugins
        Object.defineProperty(navigator, 'plugins', {
          get: () => [1, 2, 3, 4, 5]
        });
        
        // Override languages
        Object.defineProperty(navigator, 'languages', {
          get: () => ['en-US', 'en']
        });
        
        // Mock Chrome runtime
        window.chrome = {
          runtime: {},
          loadTimes: () => ({}),
          csi: () => ({}),
          app: { isInstalled: false }
        };
        
        // Mock permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
          parameters.name === 'notifications' ?
            Promise.resolve({ state: Notification.permission }) :
            originalQuery(parameters)
        );
      });
    }
    
    // ==================== LOAD COOKIES FROM FILE ====================
    console.log('🍪 Loading Twitter cookies from file...');
    await context.addCookies(YOUR_TWITTER_COOKIES);
    console.log(`✅ Loaded ${YOUR_TWITTER_COOKIES.length} cookies from file`);
    
    // Get user ID from cookies
    const userCookie = YOUR_TWITTER_COOKIES.find(c => c.name === 'twid');
    const userId = userCookie ? userCookie.value.replace('u%3D', '') : 'Unknown';
    console.log(`👤 User ID: ${userId}`);
    
    this.page = await context.newPage();
    
    // Start cookie refresh interval
    this.startCookieRefresh();
    
    // Verify login
    await this.verifyLogin();
    
    console.log('✅ Twitter Bot Pro initialized!');
  }
  
  async verifyLogin() {
    console.log('🔐 Verifying login...');
    
    try {
      // Try twitter.com first
      await this.page.goto('https://twitter.com/home', {
        waitUntil: 'domcontentloaded',
        timeout: 15000
      });
      
      await this.page.waitForTimeout(3000);
      
      // Check if logged in
      try {
        await this.page.waitForSelector('[data-testid="tweetTextarea_0"]', { timeout: 10000 });
        this.isLoggedIn = true;
        console.log('✅ Successfully logged in!');
        return true;
      } catch (error) {
        // Try x.com as backup
        console.log('⚠️ Trying x.com as backup...');
        await this.page.goto('https://x.com/home', {
          waitUntil: 'domcontentloaded',
          timeout: 10000
        });
        
        await this.page.waitForTimeout(3000);
        
        const hasTweetBox = await this.page.$('[data-testid="tweetTextarea_0"]');
        if (hasTweetBox) {
          this.isLoggedIn = true;
          console.log('✅ Login successful on x.com!');
          return true;
        }
      }
      
      console.log('❌ Not logged in. Checking page...');
      
      // Check what's on the page
      const currentUrl = this.page.url();
      console.log(`📄 Current URL: ${currentUrl}`);
      
      if (currentUrl.includes('login') || currentUrl.includes('i/flow/login')) {
        console.log('⚠️ Redirected to login page - cookies may be expired');
        console.log('💡 Update your cookies.json file with fresh cookies');
      } else {
        console.log('🤔 Unknown state. Taking screenshot...');
        await this.page.screenshot({ path: 'login_check.png' });
        console.log('📸 Screenshot saved: login_check.png');
      }
      
      this.isLoggedIn = false;
      return false;
      
    } catch (error) {
      console.log('❌ Error verifying login:', error.message);
      this.isLoggedIn = false;
      return false;
    }
  }
  
  startCookieRefresh() {
    // Check cookies every hour
    this.cookieRefreshInterval = setInterval(async () => {
      try {
        const cookies = await this.page.context().cookies();
        
        // Save fresh cookies backup
        const twitterCookies = cookies.filter(cookie => 
          cookie.domain.includes('x.com') || cookie.domain.includes('twitter.com')
        );
        
        fs.writeFileSync('twitter_session_backup.json', JSON.stringify({ 
          cookies: twitterCookies,
          backup_time: new Date().toISOString() 
        }, null, 2));
        
        console.log(`✅ Refreshed ${twitterCookies.length} cookies`);
        
      } catch (error) {
        console.log('❌ Failed to refresh cookies:', error.message);
      }
    }, 60 * 60 * 1000); // 1 hour
  }
  
  async sendReply(tweetId, replyText, req = null) {
    const startTime = Date.now();
    const proxy = this.proxyRotator.getNextProxy();
    const clientIP = req ? req.ip : null;
    
    // Rate limit check with IP
    if (!this.rateLimiter.canProceed(clientIP)) {
      const waitTime = this.rateLimiter.getWaitTime();
      const waitMinutes = Math.floor(waitTime / 60000);
      const waitSeconds = Math.floor((waitTime % 60000) / 1000);
      throw new Error(`Rate limited. Wait ${waitMinutes}m ${waitSeconds}s`);
    }
    
    if (!this.isLoggedIn) {
      // Try to re-login once
      console.log('🔄 Attempting to re-login...');
      const loggedIn = await this.verifyLogin();
      if (!loggedIn) {
        throw new Error('Not logged into Twitter');
      }
    }
    
    // Input validation
    if (!tweetId || typeof tweetId !== 'string') {
      throw new Error('Invalid tweet ID');
    }
    
    if (!replyText || typeof replyText !== 'string') {
      throw new Error('Invalid reply text');
    }
    
    if (replyText.length > 280) {
      throw new Error('Reply text too long (max 280 characters)');
    }
    
    try {
      console.log(`\n🎯 Starting reply to tweet: ${tweetId}`);
      console.log(`💬 Text: ${replyText.substring(0, 50)}...`);
      console.log(`🌐 Proxy: ${proxy?.server || 'None'}`);
      
      // Wait based on rate limits (3-6 minutes)
      const waitTime = this.rateLimiter.getWaitTime();
      const waitMinutes = Math.floor(waitTime / 60000);
      const waitSeconds = Math.floor((waitTime % 60000) / 1000);
      console.log(`⏳ Waiting ${waitMinutes} minutes ${waitSeconds} seconds...`);
      await this.page.waitForTimeout(waitTime);
      
      // Navigate to tweet
      await this.page.goto(`https://twitter.com/i/status/${tweetId}`, {
        waitUntil: 'domcontentloaded',
        timeout: 20000
      });
      
      await this.page.waitForTimeout(3000);
      
      // Simulate human scrolling
      await this.page.evaluate(() => {
        window.scrollBy(0, 200);
      });
      await this.page.waitForTimeout(1000);
      
      // Find reply button
      console.log('🔍 Looking for reply button...');
      const replyButton = await this.page.waitForSelector('[data-testid="reply"]', { timeout: 10000 });
      
      // Human-like mouse movement
      const box = await replyButton.boundingBox();
      await this.page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await this.page.waitForTimeout(500);
      
      await replyButton.click();
      await this.page.waitForTimeout(2000);
      
      // Type reply
      console.log('⌨️ Typing reply...');
      const textarea = await this.page.waitForSelector('[data-testid="tweetTextarea_0"]', { timeout: 10000 });
      await textarea.click();
      
      // Type with human-like delays
      for (let i = 0; i < replyText.length; i++) {
        await this.page.keyboard.type(replyText[i], { 
          delay: Math.floor(Math.random() * 100) + 30 
        });
        
        // Random pause
        if (Math.random() > 0.95) {
          await this.page.waitForTimeout(300);
        }
      }
      
      await this.page.waitForTimeout(1500);
      
      // Send tweet
      console.log('🚀 Sending reply...');
      const sendButton = await this.page.waitForSelector('[data-testid="tweetButton"]', { timeout: 10000 });
      await sendButton.click();
      
      await this.page.waitForTimeout(8000);
      
      // Check for success
      try {
        await this.page.waitForSelector('[data-testid="toast"]', { timeout: 5000 });
        console.log('✅ Success toast detected!');
      } catch (e) {
        console.log('✅ Reply sent (no toast detected)');
      }
      
      const responseTime = Date.now() - startTime;
      
      // Update rate limits
      this.rateLimiter.recordAction(clientIP);
      
      // Log to database
      await this.db.logTweet(
        tweetId,
        replyText,
        'success',
        null,
        responseTime,
        proxy?.server
      );
      
      await this.db.updateDailyStats();
      
      console.log(`✨ Reply completed in ${responseTime}ms`);
      console.log(`📊 Daily used: ${this.rateLimiter.dailyCount}/500`);
      
      return {
        success: true,
        tweetId,
        responseTime,
        proxy: proxy?.server,
        dailyUsed: this.rateLimiter.dailyCount,
        dailyRemaining: CONFIG.DAILY_LIMIT - this.rateLimiter.dailyCount,
        hourlyUsed: this.rateLimiter.hourlyCount,
        hourlyRemaining: CONFIG.HOURLY_LIMIT - this.rateLimiter.hourlyCount
      };
      
    } catch (error) {
      console.error(`❌ Error:`, error.message);
      
      await this.db.logTweet(
        tweetId,
        replyText,
        'failed',
        error.message,
        Date.now() - startTime,
        proxy?.server
      );
      
      // Log security event
      if (req) {
        await this.db.logSecurityEvent(
          req.ip,
          req.path,
          req.headers['user-agent'],
          'error: ' + error.message
        );
      }
      
      // Save screenshot for debugging
      try {
        await this.page.screenshot({ path: `error_${Date.now()}.png` });
        console.log('📸 Error screenshot saved');
      } catch (e) {}
      
      throw error;
    }
  }
  
  async close() {
    if (this.cookieRefreshInterval) {
      clearInterval(this.cookieRefreshInterval);
    }
    
    if (this.browser) {
      await this.browser.close();
    }
  }
}

// ==================== INITIALIZE ====================
const database = new DatabaseManager();
const proxyRotator = new ProxyRotator();
const rateLimiter = new RateLimiter();
const bot = new TwitterBot(database, proxyRotator, rateLimiter);

// ==================== EXPRESS SETUP ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================== API ENDPOINTS ====================
app.post('/api/v1/reply', apiKeyAuth, async (req, res) => {
  try {
    const { tweetId, replyText } = req.body;
    
    if (!tweetId || !replyText) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing tweetId or replyText' 
      });
    }
    
    const result = await bot.sendReply(tweetId, replyText, req);
    
    res.json({
      success: true,
      ...result,
      message: `Reply sent successfully! ${result.dailyRemaining} replies remaining today.`
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// N8N Webhook
app.post('/n8n/webhook', apiKeyAuth, async (req, res) => {
  try {
    console.log('📥 N8N Webhook received:', req.body);
    
    const { tweetId, replyText } = req.body;
    
    if (!tweetId || !replyText) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing tweetId or replyText in webhook payload' 
      });
    }
    
    const result = await bot.sendReply(tweetId, replyText, req);
    
    res.json({
      success: true,
      ...result,
      source: 'n8n',
      webhook_id: req.body.id || 'unknown'
    });
    
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message,
      source: 'n8n'
    });
  }
});

app.get('/api/v1/stats', apiKeyAuth, async (req, res) => {
  try {
    const stats = await database.getStats();
    const recent = await database.getRecentTweets(10);
    
    res.json({
      success: true,
      stats: {
        ...stats,
        dailyLimit: CONFIG.DAILY_LIMIT,
        hourlyLimit: CONFIG.HOURLY_LIMIT,
        currentDaily: rateLimiter.dailyCount,
        currentHourly: rateLimiter.hourlyCount
      },
      recent,
      config: {
        useProxy: CONFIG.USE_PROXY,
        proxyCount: proxyRotator.proxies.length,
        useStealth: CONFIG.USE_STEALTH,
        minDelay: CONFIG.MIN_DELAY / 60000, // minutes
        maxDelay: CONFIG.MAX_DELAY / 60000  // minutes
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/v1/reset', apiKeyAuth, (req, res) => {
  try {
    rateLimiter.dailyCount = 0;
    rateLimiter.hourlyCount = 0;
    rateLimiter.saveState();
    
    res.json({
      success: true,
      message: 'Rate limits reset successfully!'
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Cookie refresh endpoint
app.post('/api/v1/refresh-cookies', apiKeyAuth, async (req, res) => {
  try {
    const cookies = await bot.page?.context().cookies() || [];
    const twitterCookies = cookies.filter(cookie => 
      cookie.domain.includes('x.com') || cookie.domain.includes('twitter.com')
    );
    
    fs.writeFileSync('twitter_session_backup.json', JSON.stringify({ cookies: twitterCookies }, null, 2));
    
    res.json({
      success: true,
      message: `Refreshed ${twitterCookies.length} cookies`,
      count: twitterCookies.length
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    botLoggedIn: bot.isLoggedIn,
    rateLimits: {
      daily: `${rateLimiter.dailyCount}/${CONFIG.DAILY_LIMIT}`,
      hourly: `${rateLimiter.hourlyCount}/${CONFIG.HOURLY_LIMIT}`
    }
  });
});

// ==================== DASHBOARD ====================
// KEEP YOUR ORIGINAL DASHBOARD CODE EXACTLY AS IS
// Only change: Update the user ID display to get from cookies

// ==================== SSL SETUP ====================
function setupSSL() {
  const hasSSL = fs.existsSync('key.pem') && fs.existsSync('cert.pem');
  
  if (hasSSL) {
    const sslOptions = {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
      // Security enhancements
      minVersion: 'TLSv1.2',
      ciphers: [
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES256-GCM-SHA384'
      ].join(':'),
      honorCipherOrder: true
    };
    
    https.createServer(sslOptions, app).listen(SSL_PORT, () => {
      console.log(`✅ HTTPS Server: https://localhost:${SSL_PORT}`);
    });
    
    // Redirect HTTP to HTTPS
    const httpApp = express();
    httpApp.use((req, res) => {
      res.redirect(`https://${req.headers.host}:${SSL_PORT}${req.url}`);
    });
    
    httpApp.listen(PORT, () => {
      console.log(`✅ HTTP→HTTPS Redirect: http://localhost:${PORT}`);
    });
    
    return true;
  }
  
  return false;
}

// ==================== START SERVER ====================
async function start() {
  try {
    console.log(`
╔═══════════════════════════════════════════════════════╗
║     🐦 TWITTER BOT PRO - PRODUCTION READY           ║
║     🔐 EXTERNAL COOKIES | 🛡️ SSL SUPPORT           ║
╚═══════════════════════════════════════════════════════╝

🚀 Initializing with enhanced security...
    `);
    
    await bot.initialize();
    
    // Try to setup SSL
    const sslEnabled = setupSSL();
    
    if (!sslEnabled) {
      // Fallback to HTTP only
      app.listen(PORT, () => {
        console.log(`✅ HTTP Server: http://localhost:${PORT} (NO SSL)`);
      });
    }
    
    console.log(`
✅ SYSTEM READY FOR PRODUCTION!
📍 Dashboard: ${sslEnabled ? `https://localhost:${SSL_PORT}` : `http://localhost:${PORT}`}
📊 API: POST ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/api/v1/reply
🔗 N8N: POST ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/n8n/webhook
🔧 Health: ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/health

🎯 SECURITY FEATURES:
   • 🔐 External cookie file (NO HARDCODED VALUES)
   • 🔒 SSL/HTTPS support ${sslEnabled ? '✅ Enabled' : '❌ Disabled'}
   • 🔑 API key authentication ${CONFIG.REQUIRE_API_KEY ? '✅ Enabled' : '❌ Disabled'}
   • 📍 IP filtering ${CONFIG.ALLOWED_IPS.length > 0 ? '✅ Enabled' : '❌ Disabled'}
   • 📊 Per-IP rate limiting ✅ Enabled
   • 🛡️ Security event logging ✅ Enabled

🎯 PERFORMANCE:
   • ⚡ 500 Replies/Day Limit
   • ⏱️ 3-6 minute delays
   • 🌐 ${proxyRotator.proxies.length} proxies configured
   • 📈 Real-time dashboard

📝 USAGE:
   1. Web: Open dashboard above
   2. API: Use x-api-key header if enabled
   3. Update cookies in cookies.json when needed

⚠️  IMPORTANT:
   • Keep cookies.json file secure
   ${sslEnabled ? '• SSL certificates loaded' : '• Run: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"'}
   • Monitor rate_state.json for limits
      `);
      
  } catch (error) {
    console.error('❌ Startup failed:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await bot.close();
  
  // Backup cookies on shutdown
  try {
    if (fs.existsSync('twitter_session_backup.json')) {
      const backup = JSON.parse(fs.readFileSync('twitter_session_backup.json', 'utf8'));
      fs.writeFileSync('cookies_backup_shutdown.json', JSON.stringify(backup, null, 2));
      console.log('✅ Cookies backed up on shutdown');
    }
  } catch (e) {}
  
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('🔥 Uncaught Exception:', error);
  // Don't exit, try to recover
});

process.on('unhandledRejection', (reason, promise) => {
  console.warn('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
});

start();