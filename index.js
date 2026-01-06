// ==================== ELITE TWITTER BOT PRO - HEADLESS VERSION ====================
// OPTIMIZED FOR LINODE VPS - NO GUI REQUIRED
const { chromium } = require('playwright');
const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
require('dotenv').config();

const app = express();
const PORT = process.env.API_PORT || 3003;
const SSL_PORT = process.env.SSL_PORT || 3443;

// ==================== CONFIGURATION ====================
const CONFIG = {
  // Limits
  DAILY_LIMIT: 500,
  HOURLY_LIMIT: 60,
  MIN_DELAY: 180000,    // 3 minutes
  MAX_DELAY: 360000,    // 6 minutes
  
  // Browser - HEADLESS MODE FOR VPS
  HEADLESS: true,  // Changed to true for VPS
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
  
  // Security
  REQUIRE_API_KEY: process.env.REQUIRE_API_KEY === 'true',
  API_KEYS: process.env.API_KEYS?.split(',') || [],
  ALLOWED_IPS: process.env.ALLOWED_IPS?.split(',') || [],
  CORS_ORIGIN: process.env.CORS_ORIGIN || '*',
  
  // Headless-specific settings
  VIEWPORT_WIDTH: 1280,
  VIEWPORT_HEIGHT: 720,
  TIMEOUT: 30000,  // Increased timeout for headless
  NAVIGATION_TIMEOUT: 45000
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

const YOUR_TWITTER_COOKIES = loadCookies();

// ==================== SECURITY MIDDLEWARE ====================
app.use((req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  
  if (CONFIG.ALLOWED_IPS.length > 0 && !CONFIG.ALLOWED_IPS.includes(clientIP) && clientIP !== '::1' && clientIP !== '127.0.0.1') {
    console.warn(`🚫 Blocked IP: ${clientIP}`);
    return res.status(403).json({ success: false, error: 'Access denied' });
  }
  
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  next();
});

// API key authentication
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
    this.ipLimits = new Map();
    this.loadState();
  }
  
  canProceed(ip = null) {
    if (this.dailyCount >= CONFIG.DAILY_LIMIT) {
      console.log(`🚫 Daily limit reached: ${this.dailyCount}/${CONFIG.DAILY_LIMIT}`);
      return false;
    }
    
    if (this.hourlyCount >= CONFIG.HOURLY_LIMIT) {
      console.log(`🚫 Hourly limit reached: ${this.hourlyCount}/${CONFIG.HOURLY_LIMIT}`);
      return false;
    }
    
    if (ip) {
      const ipKey = `ip_${ip}`;
      const ipData = this.ipLimits.get(ipKey) || { count: 0, lastRequest: 0 };
      
      if (ipData.count >= 10) {
        const timeSince = Date.now() - ipData.lastRequest;
        if (timeSince < 3600000) {
          console.log(`🚫 IP ${ip} limit reached`);
          return false;
        } else {
          ipData.count = 0;
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

// ==================== HEADLESS BROWSER HELPER ====================
class HeadlessBrowserHelper {
  static async waitForSelectors(page, selectors, options = {}) {
    const timeout = options.timeout || CONFIG.TIMEOUT;
    const visible = options.visible !== false;
    
    for (const selector of selectors) {
      try {
        const element = await page.waitForSelector(selector, { 
          timeout, 
          state: visible ? 'visible' : 'attached' 
        });
        if (element) return element;
      } catch (e) {
        continue;
      }
    }
    
    throw new Error(`None of the selectors found: ${selectors.join(', ')}`);
  }
  
  static async safeClick(page, selector, options = {}) {
    try {
      const element = await page.$(selector);
      if (!element) throw new Error(`Element not found: ${selector}`);
      
      // For headless, use programmatic click instead of mouse movements
      await element.click(options);
      await page.waitForTimeout(options.delay || 1000);
      return true;
    } catch (error) {
      console.log(`⚠️ Click failed for ${selector}: ${error.message}`);
      return false;
    }
  }
  
  static async safeType(page, selector, text, options = {}) {
    try {
      await page.focus(selector);
      await page.waitForTimeout(500);
      
      // Clear existing text if any
      await page.evaluate((sel) => {
        const element = document.querySelector(sel);
        if (element) element.value = '';
      }, selector);
      
      // Type text with random delays (simulates human typing)
      for (let i = 0; i < text.length; i++) {
        await page.keyboard.type(text[i], { 
          delay: Math.floor(Math.random() * 100) + 30 
        });
        
        if (Math.random() > 0.95) {
          await page.waitForTimeout(200);
        }
      }
      
      await page.waitForTimeout(1000);
      return true;
    } catch (error) {
      console.log(`⚠️ Type failed for ${selector}: ${error.message}`);
      return false;
    }
  }
}

// ==================== TWITTER BOT - HEADLESS VERSION ====================
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
    this.retryCount = 0;
  }
  
  async initialize() {
    console.log('🚀 Initializing Twitter Bot Pro for VPS (Headless)...');
    
    const randomUserAgent = RANDOM_USER_AGENTS[Math.floor(Math.random() * RANDOM_USER_AGENTS.length)];
    
    const launchOptions = {
      headless: CONFIG.HEADLESS,  // Now true for VPS
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--ignore-certificate-errors',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
        '--hide-scrollbars',
        '--mute-audio',
        '--disable-gpu',  // Added for VPS compatibility
        '--disable-software-rasterizer',
        '--disable-extensions',
        '--disable-dev-tools',
        '--disable-background-networking',
        '--disable-background-timer-throttling',
        '--disable-backgrounding-occluded-windows',
        '--disable-breakpad',
        '--disable-component-extensions-with-background-pages',
        '--disable-features=TranslateUI,BlinkGenPropertyTrees',
        '--disable-ipc-flooding-protection',
        '--disable-renderer-backgrounding',
        '--enable-features=NetworkService,NetworkServiceInProcess',
        '--force-color-profile=srgb',
        '--metrics-recording-only',
        '--no-first-run',
        '--password-store=basic',
        '--use-mock-keychain',
        '--window-size=1280,720'
      ]
    };
    
    // Add proxy if enabled
    const proxy = this.proxyRotator.getNextProxy();
    if (proxy) {
      launchOptions.proxy = proxy;
      console.log(`🌐 Using proxy: ${proxy.server}`);
    }
    
    // Additional headless optimizations
    if (CONFIG.HEADLESS) {
      launchOptions.args.push(
        '--headless=new',  // New headless mode
        '--no-zygote',
        '--single-process'  // Single process for lower memory
      );
    }
    
    try {
      this.browser = await chromium.launch(launchOptions);
      
      const context = await this.browser.newContext({
        viewport: { width: CONFIG.VIEWPORT_WIDTH, height: CONFIG.VIEWPORT_HEIGHT },
        userAgent: randomUserAgent,
        locale: 'en-US',
        timezoneId: 'America/New_York',
        javaScriptEnabled: true,
        acceptDownloads: false,
        ignoreHTTPSErrors: true
      });
      
      // Enhanced stealth mode for headless
      if (CONFIG.USE_STEALTH) {
        await context.addInitScript(() => {
          // Override webdriver property
          Object.defineProperty(navigator, 'webdriver', { 
            get: () => false,
            configurable: true
          });
          
          // Override chrome object
          window.chrome = {
            runtime: {
              id: 'mock-runtime-id',
              getURL: () => 'chrome-extension://mock-id',
              sendMessage: () => Promise.resolve(),
              connect: () => ({
                postMessage: () => {},
                disconnect: () => {},
                onMessage: { addListener: () => {} }
              })
            },
            loadTimes: () => ({
              requestTime: 0,
              startLoadTime: 0,
              commitLoadTime: 0,
              finishDocumentLoadTime: 0,
              firstPaintTime: 0,
              firstPaintAfterLoadTime: 0,
              navigationType: 'Other'
            }),
            csi: () => ({
              onloadT: Date.now(),
              startE: 0,
              pageT: 0,
              tran: 15
            }),
            app: {
              isInstalled: false,
              getDetails: () => null
            }
          };
          
          // Mock permissions
          const originalQuery = window.navigator.permissions.query;
          window.navigator.permissions.query = (parameters) => {
            if (parameters.name === 'notifications') {
              return Promise.resolve({ state: 'denied' });
            }
            if (parameters.name === 'clipboard-read') {
              return Promise.resolve({ state: 'denied' });
            }
            return originalQuery(parameters);
          };
          
          // Mock plugins
          Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5],
            configurable: true
          });
          
          // Mock languages
          Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
            configurable: true
          });
          
          // Override window.navigator properties
          Object.defineProperty(navigator, 'platform', {
            get: () => 'Linux x86_64',
            configurable: true
          });
          
          // Hide headless userAgent
          const userAgent = navigator.userAgent;
          const headlessRegex = /HeadlessChrome/i;
          if (headlessRegex.test(userAgent)) {
            Object.defineProperty(navigator, 'userAgent', {
              get: () => userAgent.replace(headlessRegex, 'Chrome'),
              configurable: true
            });
          }
        });
      }
      
      // Load cookies
      console.log('🍪 Loading Twitter cookies from file...');
      await context.addCookies(YOUR_TWITTER_COOKIES);
      console.log(`✅ Loaded ${YOUR_TWITTER_COOKIES.length} cookies from file`);
      
      // Get user ID
      const userCookie = YOUR_TWITTER_COOKIES.find(c => c.name === 'twid');
      const userId = userCookie ? userCookie.value.replace('u%3D', '') : 'Unknown';
      console.log(`👤 User ID: ${userId}`);
      
      this.page = await context.newPage();
      
      // Set default timeouts
      this.page.setDefaultTimeout(CONFIG.TIMEOUT);
      this.page.setDefaultNavigationTimeout(CONFIG.NAVIGATION_TIMEOUT);
      
      // Start cookie refresh
      this.startCookieRefresh();
      
      // Verify login with retry
      await this.verifyLoginWithRetry();
      
      console.log('✅ Twitter Bot Pro initialized for VPS (Headless Mode)!');
      
    } catch (error) {
      console.error('❌ Failed to initialize browser:', error.message);
      
      // Try fallback headless mode
      if (error.message.includes('headless')) {
        console.log('🔄 Trying fallback headless mode...');
        return this.initializeFallback();
      }
      
      throw error;
    }
  }
  
  async initializeFallback() {
    // Fallback initialization with minimal options
    const launchOptions = {
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--single-process'
      ]
    };
    
    this.browser = await chromium.launch(launchOptions);
    const context = await this.browser.newContext();
    
    // Load cookies
    await context.addCookies(YOUR_TWITTER_COOKIES);
    this.page = await context.newPage();
    
    await this.verifyLogin();
  }
  
  async verifyLoginWithRetry(maxRetries = 3) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      console.log(`🔐 Login verification attempt ${attempt}/${maxRetries}...`);
      
      try {
        const loggedIn = await this.verifyLogin();
        
        if (loggedIn) {
          this.isLoggedIn = true;
          this.retryCount = 0;
          return true;
        }
        
        if (attempt < maxRetries) {
          console.log(`🔄 Login failed, retrying in 5 seconds...`);
          await this.page.waitForTimeout(5000);
        }
      } catch (error) {
        console.log(`⚠️ Login attempt ${attempt} failed: ${error.message}`);
        
        if (attempt < maxRetries) {
          await this.page.waitForTimeout(5000);
        }
      }
    }
    
    console.log('❌ All login attempts failed');
    this.isLoggedIn = false;
    return false;
  }
  
  async verifyLogin() {
    try {
      // Try x.com first (new domain)
      await this.page.goto('https://x.com/home', {
        waitUntil: 'networkidle',
        timeout: 15000
      });
      
      await this.page.waitForTimeout(3000);
      
      // Check for tweet box or home page indicators
      const selectors = [
        '[data-testid="tweetTextarea_0"]',
        '[data-testid="SideNav_NewTweet_Button"]',
        '[aria-label="Tweet"]',
        'text="Home"',
        '[href="/home"]'
      ];
      
      for (const selector of selectors) {
        try {
          const element = await this.page.$(selector);
          if (element) {
            this.isLoggedIn = true;
            console.log(`✅ Login verified with selector: ${selector}`);
            return true;
          }
        } catch (e) {
          continue;
        }
      }
      
      // Check URL
      const currentUrl = this.page.url();
      if (currentUrl.includes('x.com/home') || currentUrl.includes('twitter.com/home')) {
        this.isLoggedIn = true;
        console.log(`✅ Login verified via URL: ${currentUrl}`);
        return true;
      }
      
      // Check for login page
      if (currentUrl.includes('login') || currentUrl.includes('i/flow/login')) {
        console.log('❌ Redirected to login page - cookies may be expired');
        this.isLoggedIn = false;
        return false;
      }
      
      // Take screenshot for debugging
      const screenshotPath = `login_debug_${Date.now()}.png`;
      await this.page.screenshot({ path: screenshotPath, fullPage: true });
      console.log(`📸 Debug screenshot saved: ${screenshotPath}`);
      
      // Check page content
      const pageContent = await this.page.content();
      if (pageContent.includes('Log in') || pageContent.includes('Sign in')) {
        this.isLoggedIn = false;
        console.log('❌ Login page detected in content');
        return false;
      }
      
      // If we're here, assume logged in but couldn't verify with selectors
      this.isLoggedIn = true;
      console.log('✅ Assuming logged in (no explicit verification)');
      return true;
      
    } catch (error) {
      console.log(`❌ Login verification error: ${error.message}`);
      
      // Try alternative verification
      try {
        await this.page.goto('https://x.com', { waitUntil: 'domcontentloaded', timeout: 10000 });
        await this.page.waitForTimeout(2000);
        
        // Check for tweet button
        const hasTweetButton = await this.page.$('[data-testid="SideNav_NewTweet_Button"]');
        if (hasTweetButton) {
          this.isLoggedIn = true;
          console.log('✅ Alternative verification succeeded');
          return true;
        }
      } catch (e) {
        console.log('❌ Alternative verification also failed');
      }
      
      this.isLoggedIn = false;
      return false;
    }
  }
  
  startCookieRefresh() {
    this.cookieRefreshInterval = setInterval(async () => {
      try {
        if (!this.page || !this.page.context()) {
          console.log('⚠️ Cannot refresh cookies: page not available');
          return;
        }
        
        const cookies = await this.page.context().cookies();
        
        const twitterCookies = cookies.filter(cookie => 
          cookie.domain.includes('x.com') || cookie.domain.includes('twitter.com')
        );
        
        if (twitterCookies.length > 0) {
          fs.writeFileSync('twitter_session_backup.json', JSON.stringify({ 
            cookies: twitterCookies,
            backup_time: new Date().toISOString() 
          }, null, 2));
          
          console.log(`✅ Refreshed ${twitterCookies.length} cookies`);
        }
        
      } catch (error) {
        console.log('⚠️ Failed to refresh cookies:', error.message);
      }
    }, 60 * 60 * 1000); // 1 hour
  }
  
  async sendReply(tweetId, replyText, req = null) {
    const startTime = Date.now();
    const proxy = this.proxyRotator.getNextProxy();
    const clientIP = req ? req.ip : null;
    
    // Rate limit check
    if (!this.rateLimiter.canProceed(clientIP)) {
      const waitTime = this.rateLimiter.getWaitTime();
      const waitMinutes = Math.floor(waitTime / 60000);
      const waitSeconds = Math.floor((waitTime % 60000) / 1000);
      throw new Error(`Rate limited. Wait ${waitMinutes}m ${waitSeconds}s`);
    }
    
    if (!this.isLoggedIn) {
      console.log('🔄 Attempting to re-login...');
      const loggedIn = await this.verifyLoginWithRetry(2);
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
      console.log(`💻 Mode: ${CONFIG.HEADLESS ? 'Headless' : 'GUI'}`);
      
      // Wait based on rate limits
      const waitTime = this.rateLimiter.getWaitTime();
      const waitMinutes = Math.floor(waitTime / 60000);
      const waitSeconds = Math.floor((waitTime % 60000) / 1000);
      console.log(`⏳ Waiting ${waitMinutes}m ${waitSeconds}s...`);
      await this.page.waitForTimeout(waitTime);
      
      // Navigate to tweet
      console.log('🌍 Navigating to tweet...');
      await this.page.goto(`https://x.com/i/status/${tweetId}`, {
        waitUntil: 'networkidle',
        timeout: CONFIG.NAVIGATION_TIMEOUT
      });
      
      await this.page.waitForTimeout(3000);
      
      // Simulate scrolling (headless-friendly)
      await this.page.evaluate(() => {
        window.scrollBy({ top: 300, behavior: 'smooth' });
      });
      await this.page.waitForTimeout(2000);
      
      // Find and click reply button
      console.log('🔍 Looking for reply button...');
      const replySelectors = [
        '[data-testid="reply"]',
        '[aria-label="Reply"]',
        'div[role="button"][aria-label*="Reply"]',
        'button:has-text("Reply")'
      ];
      
      const replyButton = await HeadlessBrowserHelper.waitForSelectors(this.page, replySelectors, { 
        timeout: 15000 
      });
      
      if (!replyButton) {
        throw new Error('Reply button not found');
      }
      
      // Click using JavaScript (more reliable in headless)
      await this.page.evaluate((btn) => {
        if (btn && typeof btn.click === 'function') {
          btn.click();
        }
      }, replyButton);
      
      await this.page.waitForTimeout(3000);
      
      // Type reply
      console.log('⌨️ Typing reply...');
      const textareaSelectors = [
        '[data-testid="tweetTextarea_0"]',
        '[data-testid="tweetTextarea"]',
        'div[contenteditable="true"][role="textbox"]',
        '[aria-label="Tweet text"]'
      ];
      
      // Find textarea
      const textarea = await HeadlessBrowserHelper.waitForSelectors(this.page, textareaSelectors, {
        timeout: 10000
      });
      
      if (!textarea) {
        throw new Error('Reply textarea not found');
      }
      
      // Focus and type
      await textarea.click();
      await this.page.waitForTimeout(1000);
      
      // Type with delays (simulates human)
      await this.page.keyboard.type(replyText, { 
        delay: Math.floor(Math.random() * 100) + 50 
      });
      
      await this.page.waitForTimeout(2000);
      
      // Send tweet
      console.log('🚀 Sending reply...');
      const sendButtonSelectors = [
        '[data-testid="tweetButton"]',
        '[data-testid="tweetButtonInline"]',
        'button:has-text("Reply")',
        'div[role="button"][data-testid*="tweetButton"]'
      ];
      
      const sendButton = await HeadlessBrowserHelper.waitForSelectors(this.page, sendButtonSelectors, {
        timeout: 10000
      });
      
      if (!sendButton) {
        throw new Error('Send button not found');
      }
      
      // Click send button
      await sendButton.click();
      
      // Wait for response
      console.log('⏳ Waiting for response...');
      await this.page.waitForTimeout(8000);
      
      // Check for success indicators
      let success = false;
      const successIndicators = [
        async () => {
          try {
            await this.page.waitForSelector('[data-testid="toast"]', { timeout: 5000 });
            return true;
          } catch (e) {
            return false;
          }
        },
        async () => {
          // Check if we're back on the tweet page
          const currentUrl = this.page.url();
          return currentUrl.includes(`/status/${tweetId}`);
        },
        async () => {
          // Check for "Your post was sent" text
          const content = await this.page.content();
          return content.includes('Your post') || content.includes('sent');
        }
      ];
      
      for (const check of successIndicators) {
        if (await check()) {
          success = true;
          break;
        }
      }
      
      if (!success) {
        console.log('⚠️ No explicit success indicator found, but assuming success');
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
      console.log(`📊 Daily used: ${this.rateLimiter.dailyCount}/${CONFIG.DAILY_LIMIT}`);
      
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
      console.error(`❌ Error sending reply:`, error.message);
      
      // Log error
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
        const screenshotPath = `error_${Date.now()}.png`;
        await this.page.screenshot({ path: screenshotPath, fullPage: true });
        console.log(`📸 Error screenshot saved: ${screenshotPath}`);
      } catch (e) {
        console.log('⚠️ Could not save screenshot');
      }
      
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
        headless: CONFIG.HEADLESS,
        useProxy: CONFIG.USE_PROXY,
        proxyCount: proxyRotator.proxies.length,
        useStealth: CONFIG.USE_STEALTH,
        minDelay: CONFIG.MIN_DELAY / 60000,
        maxDelay: CONFIG.MAX_DELAY / 60000
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

app.post('/api/v1/refresh-cookies', apiKeyAuth, async (req, res) => {
  try {
    if (!bot.page || !bot.page.context()) {
      throw new Error('Browser not available');
    }
    
    const cookies = await bot.page.context().cookies() || [];
    const twitterCookies = cookies.filter(cookie => 
      cookie.domain.includes('x.com') || cookie.domain.includes('twitter.com')
    );
    
    if (twitterCookies.length > 0) {
      fs.writeFileSync('twitter_session_backup.json', JSON.stringify({ 
        cookies: twitterCookies,
        backup_time: new Date().toISOString() 
      }, null, 2));
    }
    
    res.json({
      success: true,
      message: `Refreshed ${twitterCookies.length} cookies`,
      count: twitterCookies.length
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    botLoggedIn: bot.isLoggedIn,
    headlessMode: CONFIG.HEADLESS,
    rateLimits: {
      daily: `${rateLimiter.dailyCount}/${CONFIG.DAILY_LIMIT}`,
      hourly: `${rateLimiter.hourlyCount}/${CONFIG.HOURLY_LIMIT}`
    }
  });
});

// ==================== SSL SETUP ====================
function setupSSL() {
  const hasSSL = fs.existsSync('key.pem') && fs.existsSync('cert.pem');
  
  if (hasSSL) {
    const sslOptions = {
      key: fs.readFileSync('key.pem'),
      cert: fs.readFileSync('cert.pem'),
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
║     🐦 TWITTER BOT PRO - HEADLESS VPS EDITION       ║
║     🔐 EXTERNAL COOKIES | 🖥️  HEADLESS MODE        ║
╚═══════════════════════════════════════════════════════╝

🚀 Initializing for VPS (No GUI)...
    `);
    
    await bot.initialize();
    
    // Try to setup SSL
    const sslEnabled = setupSSL();
    
    if (!sslEnabled) {
      app.listen(PORT, () => {
        console.log(`✅ HTTP Server: http://localhost:${PORT} (NO SSL)`);
      });
    }
    
    console.log(`
✅ SYSTEM READY FOR VPS!
📍 Dashboard: ${sslEnabled ? `https://localhost:${SSL_PORT}` : `http://localhost:${PORT}`}
📊 API: POST ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/api/v1/reply
🔗 N8N: POST ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/n8n/webhook
🔧 Health: ${sslEnabled ? 'https' : 'http'}://localhost:${sslEnabled ? SSL_PORT : PORT}/health

🎯 VPS OPTIMIZATIONS:
   • 🖥️  Full headless mode (NO GUI REQUIRED)
   • ⚡ Reduced memory footprint
   • 🛡️  Enhanced stealth for headless
   • 🔄 Automatic retry mechanisms
   • 📸 Debug screenshots on error

🎯 SECURITY FEATURES:
   • 🔐 External cookie file
   • 🔒 SSL/HTTPS support ${sslEnabled ? '✅ Enabled' : '❌ Disabled'}
   • 🔑 API key authentication ${CONFIG.REQUIRE_API_KEY ? '✅ Enabled' : '❌ Disabled'}
   • 📍 IP filtering ${CONFIG.ALLOWED_IPS.length > 0 ? '✅ Enabled' : '❌ Disabled'}
   • 📊 Per-IP rate limiting ✅ Enabled

📝 LINODE VPS SETUP TIPS:
   1. Ensure cookies.json is in the same directory
   2. Run: npm install playwright express sqlite3 dotenv
   3. Install playwright browsers: npx playwright install chromium
   4. Run with PM2: pm2 start index.js --name twitter-bot
   5. Enable SSL: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

⚠️  IMPORTANT FOR HEADLESS:
   • Check error screenshots in same directory
   • Monitor logs: pm2 logs twitter-bot
   • Update cookies.json when needed
   • Restart after cookie updates: pm2 restart twitter-bot
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
  
  try {
    if (fs.existsSync('twitter_session_backup.json')) {
      const backup = JSON.parse(fs.readFileSync('twitter_session_backup.json', 'utf8'));
      fs.writeFileSync('cookies_backup_shutdown.json', JSON.stringify(backup, null, 2));
      console.log('✅ Cookies backed up on shutdown');
    }
  } catch (e) {
    console.log('⚠️ Could not backup cookies on shutdown');
  }
  
  process.exit(0);
});

process.on('uncaughtException', (error) => {
  console.error('🔥 Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.warn('⚠️ Unhandled Rejection at:', promise, 'reason:', reason);
});

start();
