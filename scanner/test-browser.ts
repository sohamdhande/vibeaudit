import puppeteer from 'puppeteer';
import os from 'os';
import path from 'path';
import fs from 'fs';

async function test() {
  console.log('Platform:', process.platform);
  
  // Create a fresh temp user data dir
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pptr-'));
  console.log('User data dir:', tmpDir);

  // Test with system Chrome + clean profile
  console.log('\n=== Test: System Chrome with clean profile ===');
  try {
    const browser = await puppeteer.launch({
      headless: true,
      executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      args: [
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        `--user-data-dir=${tmpDir}`,
      ],
    });
    console.log('✅ Browser launched');
    const page = await browser.newPage();
    
    console.log('Trying https://example.com ...');
    try {
      await page.goto('https://example.com', { timeout: 10000 });
      console.log('✅ SUCCESS: example.com');
    } catch (e: any) {
      console.log('❌ FAILED:', e.message.split('\n')[0]);
    }

    console.log('Trying http://localhost:8888 ...');
    try {
      await page.goto('http://localhost:8888', { timeout: 5000 });
      console.log('✅ SUCCESS: localhost:8888');
    } catch (e: any) {
      console.log('❌ FAILED:', e.message.split('\n')[0]);
    }
    
    await browser.close();
  } catch (e: any) {
    console.log('❌ Launch failed:', e.message.substring(0, 500));
  }

  // Cleanup
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

test().catch(console.error);
