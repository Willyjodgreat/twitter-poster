const { chromium } = require('playwright');
const fs = require('fs');
const os = require('os');
const path = require('path');

(async () => {
  const userDataDir = path.join(os.homedir(), 'AppData', 'Local', 'Google', 'Chrome', 'User Data');
  
  console.log('🔍 Using your real Chrome profile...');
  console.log('Profile path:', userDataDir);
  
  const browser = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    args: [
      '--no-sandbox',
      '--disable-blink-features=AutomationControlled'
    ]
  });
  
  const page = await browser.newPage();
  
  console.log('🌐 Opening Twitter...');
  await page.goto('https://twitter.com/home');
  
  console.log('\n=== CHECK ===');
  console.log('1. Are you ALREADY logged in? (if you use Chrome normally)');
  console.log('2. If yes, bot can use your existing session');
  console.log('3. If no, login manually now');
  console.log('4. Press Enter when ready');
  
  await new Promise(resolve => {
    process.stdin.once('data', resolve);
  });
  
  // Save cookies from real Chrome
  const cookies = await browser.cookies();
  fs.writeFileSync('twitter_session.json', JSON.stringify({cookies}, null, 2));
  
  console.log(`✅ Saved ${cookies.length} cookies from real Chrome`);
  
  // Don't close - keep Chrome open
  console.log('⚠️  Keep this Chrome window open!');
  console.log('🚀 Now run your bot in another terminal: node index.js');
  
  // Keep script running
  await new Promise(() => {});
})();
