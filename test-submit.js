// test-submit.js — quick node test to POST to the demo submit endpoint
const fetch = require('node-fetch');

(async () => {
  const payload = {
    email: "student@example.com",
    secret: "itison",
    url: "https://tds-llm-analysis.s-anand.net/demo",
    answer: "anything you want"
  };

  try {
    const resp = await fetch('https://tds-llm-analysis.s-anand.net/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      timeout: 30000
    });
    const text = await resp.text();
    console.log('status', resp.status);
    console.log('body', text);
  } catch (err) {
    console.error('Error posting to submit:', err);
  }
})();