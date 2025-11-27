// server.js (enhanced script scanning + base64 detection)
// Replaces previous file. Use same instructions: set APP_SECRET env var and run `node server.js`

const express = require('express');
const fetch = require('node-fetch'); // node-fetch v2
const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');
const pdfParse = require('pdf-parse');

const APP_SECRET = process.env.APP_SECRET || 'replace_me_secret';
const TEMP_DIR = path.join(__dirname, 'tmp_files');
if (!fs.existsSync(TEMP_DIR)) fs.mkdirSync(TEMP_DIR, { recursive: true });

const app = express();
app.use(express.json({ limit: '1mb' }));

function validatePayload(body) {
  if (!body || typeof body !== 'object') return false;
  if (!body.email || !body.secret || !body.url) return false;
  return true;
}

// helper: try to detect base64 PDF inline (data:application/pdf;base64,...)
function findDataPdfInText(txt) {
  const m = txt.match(/data:application\/pdf;base64,([A-Za-z0-9+/=\r\n]+)/i);
  if (m && m[1]) return m[1].replace(/\s+/g, '');
  return null;
}

// helper: try to find any long base64 blob (heuristic)
function findLongBase64Blob(txt, minLen = 200) {
  // base64 charset (plus possible newlines/spaces). Look for long sequences of base64 chars.
  const re = /([A-Za-z0-9+/=\r\n]{200,})/g;
  let match;
  while ((match = re.exec(txt)) !== null) {
    const candidate = match[1].replace(/\s+/g, '');
    // quick sanity: length mod 4 often 0 (but not enforced). Also must contain some '=' padding sometimes.
    if (candidate.length >= minLen && /^[A-Za-z0-9+/=]+$/.test(candidate)) {
      return candidate;
    }
  }
  return null;
}

// helper: try to parse JSON block from text (first {...})
function extractJsonBlock(txt) {
  const m = txt.match(/\{[\s\S]*\}/);
  if (!m) return null;
  try {
    return JSON.parse(m[0]);
  } catch (e) {
    return null;
  }
}

app.post('/webhook', async (req, res) => {
  const payload = req.body;
  if (!validatePayload(payload)) return res.status(400).json({ error: 'Invalid JSON or missing fields (email, secret, url required)' });
  if (payload.secret !== APP_SECRET) return res.status(403).json({ error: 'Invalid secret' });

  res.status(200).json({ accepted: true });

  (async () => {
    const start = Date.now();
    const JOB_TIMEOUT_MS = 170000;
    let browser;
    const jobTimer = setTimeout(async () => {
      console.error('JOB TIMEOUT reached. Attempting to close browser.');
      try { if (browser) await browser.close(); } catch(e) {}
    }, JOB_TIMEOUT_MS);

    try {
      browser = await puppeteer.launch({ args: ['--no-sandbox','--disable-setuid-sandbox'], headless: true });
      const page = await browser.newPage();

      console.log('Opening quiz URL:', payload.url);
      await page.goto(payload.url, { waitUntil: 'networkidle2', timeout: 60000 });

      // find submit url as before
      let submitUrl = await page.evaluate(() => {
        const a = Array.from(document.querySelectorAll('a[href]')).find(x => /submit/i.test(x.href));
        if (a) return a.href;
        const f = Array.from(document.querySelectorAll('form[action]')).find(x => /submit/i.test(x.action));
        if (f) return f.action;
        const m = document.body.innerText.match(/https?:\/\/[^\s'"]+\/[^\s'"]*submit[^\s'"]*/i);
        if (m) return m[0];
        return null;
      });
      console.log('submitUrl found:', submitUrl);

      // 1) try direct pdf link in DOM/text
      let pdfUrl = await page.evaluate(() => {
        const pdfLink = Array.from(document.querySelectorAll('a[href]')).find(a => /\.pdf(\?|$)/i.test(a.href));
        if (pdfLink) return pdfLink.href;
        const match = document.body.innerText.match(/https?:\/\/[^\s'"]+\.pdf[^\s'"]*/i);
        if (match) return match[0];
        return null;
      });
      console.log('pdfUrl found (direct search):', pdfUrl);

      // 2) fetch all scripts (inline and external) and search them thoroughly
      if (!pdfUrl) {
        console.log('Gathering inline scripts and external script sources...');
        // get inline script contents and list of script srcs
        const { inlineScripts, scriptSrcs, pageHtml } = await page.evaluate(() => {
          const inline = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.innerText || '');
          const srcs = Array.from(document.querySelectorAll('script[src]')).map(s => s.getAttribute('src') || '').filter(Boolean);
          return { inlineScripts: inline, scriptSrcs: srcs, pageHtml: document.documentElement.outerHTML || document.documentElement.innerHTML || '' };
        });

        // Save page HTML for debugging
        try {
          const htmlFile = path.join(TEMP_DIR, `page_${Date.now()}.html`);
          fs.writeFileSync(htmlFile, await page.content(), 'utf8');
          console.log('Saved page HTML to', htmlFile);
        } catch (e) {
          console.warn('Could not save page HTML:', e.message || e);
        }

        // Combine inline scripts to search
        let combinedText = inlineScripts.join('\n\n');

        // Fetch external scripts (resolve relative URLs)
        if (scriptSrcs.length > 0) {
          console.log('Found external scripts:', scriptSrcs.length);
          for (const src of scriptSrcs) {
            try {
              const resolved = new URL(src, payload.url).href;
              console.log('Fetching external script:', resolved);
              const resp = await fetch(resolved, { timeout: 20000 });
              if (resp.ok) {
                const t = await resp.text();
                combinedText += '\n\n' + t;
              } else {
                console.warn('Failed fetching script', resolved, 'status', resp.status);
              }
            } catch (e) {
              console.warn('Error fetching script src', src, e.message || e);
            }
          }
        }

        // Also include visible body text as fallback
        try {
          const bodyText = await page.evaluate(() => document.body ? document.body.innerText || '' : '');
          combinedText += '\n\n' + bodyText;
        } catch (e) { /* ignore */ }

        // Save combined scripts for debugging
        try {
          const combinedFile = path.join(TEMP_DIR, `scripts_combined_${Date.now()}.txt`);
          fs.writeFileSync(combinedFile, combinedText, 'utf8');
          console.log('Saved combined script text to', combinedFile);
        } catch (e) {
          console.warn('Could not save combined scripts:', e.message || e);
        }

        // 2a) look for data:application/pdf;base64,... pattern
        const dataPdfB64 = findDataPdfInText(combinedText);
        if (dataPdfB64) {
          console.log('Found data:application/pdf;base64 in scripts.');
          // write pdf file
          const pdfBuffer = Buffer.from(dataPdfB64, 'base64');
          const pdfFilename = path.join(TEMP_DIR, `embedded_${Date.now()}.pdf`);
          fs.writeFileSync(pdfFilename, pdfBuffer);
          console.log('Wrote embedded PDF to', pdfFilename, 'bytes:', pdfBuffer.length);
          // set pdfUrl to local file path via file:// so later parsing reads buffer instead
          pdfUrl = 'file://' + pdfFilename;
        }
        // 2b) look for explicit atob(...) occurrences (double/single/backtick)
        if (!pdfUrl) {
          // find all atob("..."), atob('...'), atob(`...`) occurrences and try decode
          const atobMatches = [];
          const atobRe = /atob\(\s*(`[\s\S]*?`|"[\s\S]*?"|'[\s\S]*?')\s*\)/g;
          let m;
          while ((m = atobRe.exec(combinedText)) !== null) {
            let inner = m[1];
            // strip surrounding quotes/backticks
            if ((inner.startsWith('`') && inner.endsWith('`')) || (inner.startsWith('"') && inner.endsWith('"')) || (inner.startsWith("'") && inner.endsWith("'"))) {
              inner = inner.slice(1, -1);
            }
            atobMatches.push(inner);
          }
          // decode any found atob strings (they are base64)
          for (const b64 of atobMatches) {
            const candidate = b64.replace(/\s+/g, '');
            try {
              const buf = Buffer.from(candidate, 'base64');
              // quick check: does buffer start with PDF header %PDF
              if (buf.slice(0,4).toString() === '%PDF') {
                const pdfFilename = path.join(TEMP_DIR, `decoded_atob_${Date.now()}.pdf`);
                fs.writeFileSync(pdfFilename, buf);
                console.log('Decoded atob(...) to PDF file', pdfFilename);
                pdfUrl = 'file://' + pdfFilename;
                break;
              } else {
                // save decoded text for inspection (maybe it's JSON)
                const txtFile = path.join(TEMP_DIR, `decoded_atob_text_${Date.now()}.txt`);
                fs.writeFileSync(txtFile, buf.toString('utf8'));
                console.log('Decoded atob(...) to text file', txtFile);
                // look for pdf url inside
                const txt = buf.toString('utf8');
                const pdfMatch = txt.match(/https?:\/\/[^\s'"]+\.pdf[^\s'"]*/i);
                if (pdfMatch) {
                  pdfUrl = pdfMatch[0];
                  console.log('Found PDF URL inside decoded atob text:', pdfUrl);
                  break;
                }
                // try JSON parse
                const parsed = extractJsonBlock(txt);
                if (parsed) {
                  if (parsed.url && /\.pdf/i.test(parsed.url)) { pdfUrl = parsed.url; break; }
                  if (parsed.file && /\.pdf/i.test(parsed.file)) { pdfUrl = parsed.file; break; }
                }
              }
            } catch (e) {
              // ignore decode errors
            }
          }
        }
        // 2c) if still no pdfUrl, try heuristics: long base64 blob
        if (!pdfUrl) {
          const longB64 = findLongBase64Blob(combinedText, 300); // require longer for safety
          if (longB64) {
            console.log('Found long base64 blob in scripts; attempting to decode as PDF...');
            try {
              const buf = Buffer.from(longB64, 'base64');
              if (buf.slice(0,4).toString() === '%PDF') {
                const pdfFilename = path.join(TEMP_DIR, `long_b64_${Date.now()}.pdf`);
                fs.writeFileSync(pdfFilename, buf);
                console.log('Decoded long base64 blob to PDF file', pdfFilename);
                pdfUrl = 'file://' + pdfFilename;
              } else {
                console.log('Long base64 blob decoded but did not start with %PDF; skipping.');
              }
            } catch (e) {
              console.warn('Error decoding long base64 blob:', e.message || e);
            }
          }
        }

        // 2d) attempt JSON parse of combined text to find url fields
        if (!pdfUrl) {
          const parsed = extractJsonBlock(combinedText);
          if (parsed) {
            if (parsed.url && typeof parsed.url === 'string' && /\.pdf/i.test(parsed.url)) {
              pdfUrl = parsed.url;
              console.log('Found pdf url in parsed JSON "url":', pdfUrl);
            } else if (parsed.file && typeof parsed.file === 'string' && /\.pdf/i.test(parsed.file)) {
              pdfUrl = parsed.file;
              console.log('Found pdf url in parsed JSON "file":', pdfUrl);
            } else {
              console.log('Parsed JSON found but did not contain a .pdf url.');
            }
            if (!submitUrl && parsed.submit_url) submitUrl = parsed.submit_url;
            if (!submitUrl && parsed.url && /submit/i.test(parsed.url)) submitUrl = parsed.url;
          } else {
            console.log('No JSON block parseable from combined scripts.');
          }
        }
      } // end script scanning block

      // console.log('Final pdfUrl to use:', pdfUrl);

      // if (!pdfUrl) {
      //   console.error('No PDF link found on the quiz page, in scripts, or embedded base64. Job stops here.');
      //   try { await browser.close(); } catch(e){}
      //   clearTimeout(jobTimer);
      //   return;
      // }

      console.log('Final pdfUrl to use:', pdfUrl);

      if (!pdfUrl) {
       // --- DEMO / fallback: if page asked to POST JSON to submitUrl (simple demo), do that ---
        if (submitUrl) {
         try {
            console.log('No PDF found — demo fallback: submitting a simple answer to submitUrl:', submitUrl);
            const demoSubmitPayload = {
              email: payload.email,
              secret: payload.secret,
              url: payload.url,
              answer: "demo-answer-from-server"
           };
           const demoResp = await fetch(submitUrl, {
             method: 'POST',
             headers: { 'Content-Type': 'application/json' },
             body: JSON.stringify(demoSubmitPayload),
             timeout: 60000
           });
           const demoText = await demoResp.text();
           console.log('Demo submit response status:', demoResp.status, 'body:', demoText);
         } catch (err) {
           console.error('Error submitting demo fallback payload:', err);
         } finally {
           try { await browser.close(); } catch(e){}
           clearTimeout(jobTimer);
           return;
         }
       }

       // If no submitUrl either, stop the job
       console.error('No PDF link found on the quiz page, in scripts, or embedded base64. Job stops here.');
       try { await browser.close(); } catch(e){}
       clearTimeout(jobTimer);
        return;
      }


      // 3) Download or read the PDF (support file:// local files created above)
      let pdfBuffer;
      if (pdfUrl.startsWith('file://')) {
        const localPath = pdfUrl.replace('file://', '');
        console.log('Reading local PDF file', localPath);
        pdfBuffer = fs.readFileSync(localPath);
      } else {
        console.log('Downloading PDF from', pdfUrl);
        const pdfResp = await fetch(pdfUrl, { timeout: 60000 });
        if (!pdfResp.ok) {
          console.error('Failed to download PDF, status:', pdfResp.status);
          try { await browser.close(); } catch(e){}
          clearTimeout(jobTimer);
          return;
        }
        pdfBuffer = await pdfResp.buffer();
      }

      // optionally save PDF for debugging
      try {
        const savePath = path.join(TEMP_DIR, `quiz_saved_${Date.now()}.pdf`);
        fs.writeFileSync(savePath, pdfBuffer);
        console.log('Saved PDF copy to', savePath);
      } catch (e) { /* ignore */ }

      // 4) parse PDF and extract page 2 text
      console.log('Parsing PDF...');
      const data = await pdfParse(pdfBuffer);
      const allText = data.text || '';
      const pages = allText.split('\f');
      const page2Text = pages[1] || '';
      console.log('Extracted page2 text length:', page2Text.length);

      // 5) same table-parsing logic as before
      const lines = page2Text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      let sum = 0;
      let foundHeader = null;
      let valueColIndex = -1;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/value/i.test(line) && line.split(/\s{2,}/).length >= 2) {
          foundHeader = line;
          const headers = line.split(/\s{2,}/).map(h => h.trim().toLowerCase());
          valueColIndex = headers.findIndex(h => h.includes('value'));
          for (let j = i + 1; j < lines.length; j++) {
            const dataLine = lines[j];
            if (/^[A-Za-z\s\-]+$/.test(dataLine) && dataLine.split(/\s{2,}/).length <= 1) break;
            const cols = dataLine.split(/\s{2,}/).map(c => c.trim());
            if (valueColIndex >= 0 && valueColIndex < cols.length) {
              const raw = cols[valueColIndex].replace(/[,₹$€£]/g, '').trim();
              const m = raw.match(/-?\d+(\.\d+)?/);
              if (m) {
                const num = parseFloat(m[0]);
                if (!Number.isNaN(num)) sum += num;
              }
            }
          }
          break;
        }
      }

      if (foundHeader === null) {
        console.warn('Header with "value" not found on page 2. Falling back to summing all numbers on page 2 (may be wrong).');
        const allNums = page2Text.match(/-?\d{1,3}(?:[,.\d]*\d)?/g) || [];
        sum = 0;
        for (const t of allNums) {
          const cleaned = t.replace(/,/g, '');
          const n = parseFloat(cleaned);
          if (!Number.isNaN(n)) sum += n;
        }
      }

      const answer = (Math.round(sum) === sum) ? Math.round(sum) : parseFloat(sum.toFixed(6));
      console.log('Computed answer (sum of value column, page 2):', answer);

      // 6) submit if submitUrl exists
      if (!submitUrl) {
        console.error('No submit URL available on the quiz page; cannot submit answer. Job ends.');
      } else {
        const submitPayload = { email: payload.email, secret: payload.secret, url: payload.url, answer: answer };
        console.log('Submitting payload to', submitUrl);
        try {
          const submitResp = await fetch(submitUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(submitPayload),
            timeout: 60000
          });
          const text = await submitResp.text();
          console.log('Submit response status:', submitResp.status, 'body snippet:', text.slice(0,1000));
        } catch (e) {
          console.error('Error submitting answer:', e);
        }
      }

      // cleanup created local PDF files older than some time? (not implemented here)
      clearTimeout(jobTimer);
      try { await browser.close(); } catch(e){}
      console.log('Background job finished in', (Date.now() - start), 'ms');

    } catch (err) {
      clearTimeout(jobTimer);
      console.error('Background job error:', err);
      try { if (browser) await browser.close(); } catch(e){}
    }
  })();

});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Webhook server listening on port ${PORT}`));