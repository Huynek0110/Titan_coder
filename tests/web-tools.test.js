'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  WebTools,
  htmlToText,
  isPrivateAddress,
  parseDuckDuckGoHtml,
  redact,
} = require('../src/main/tools/web-tools');

function publicLookup() {
  return async () => [{ address: '93.184.216.34', family: 4 }];
}

function fakeResponse(status, body, headers = {}) {
  return {
    status,
    headers,
    async text() { return body; },
  };
}

test('web tool definitions are bounded OpenAI function schemas', () => {
  const tools = new WebTools().definitions();
  assert.deepEqual(tools.map((tool) => tool.function.name), ['web_search', 'web_fetch', 'http_request']);
  for (const tool of tools) {
    assert.equal(tool.type, 'function');
    assert.equal(tool.function.parameters.type, 'object');
    assert.equal(tool.function.parameters.additionalProperties, false);
  }
});

test('HTML extraction removes executable content and decodes entities', () => {
  const text = htmlToText('<script>window.secret = 1</script><style>.x{}</style><h1>Hello &amp; hi</h1><p>World<br>next</p>');
  assert.match(text, /Hello & hi/);
  assert.match(text, /World\nnext/);
  assert.doesNotMatch(text, /secret|style|script/i);
});

test('private, link-local, metadata, and reserved addresses fail closed', () => {
  for (const address of [
    '127.0.0.1',
    '10.1.2.3',
    '172.16.0.1',
    '192.168.1.1',
    '169.254.169.254',
    '0.0.0.0',
    '224.0.0.1',
    '::1',
    'fc00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
  ]) assert.equal(isPrivateAddress(address), true, address);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isPrivateAddress('2001:4860:4860::8888'), false);
});

test('redaction removes headers, token fields, query values, and bearer tokens', () => {
  const value = redact({
    Authorization: 'Bearer very-secret-value',
    Cookie: 'session=secret',
    nested: { api_key: 'key-secret', note: 'Authorization: Bearer another-secret' },
    url: 'https://example.test/path?token=query-secret&safe=yes',
  });
  assert.equal(value.Authorization, '[REDACTED]');
  assert.equal(value.Cookie, '[REDACTED]');
  assert.equal(value.nested.api_key, '[REDACTED]');
  assert.match(value.nested.note, /\[REDACTED\]/);
  assert.doesNotMatch(JSON.stringify(value), /very-secret-value|key-secret|query-secret|another-secret/);
});

test('DuckDuckGo HTML parser returns only title, URL, and snippet', () => {
  const fixture = `
    <div class="result">
      <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage%3Ftoken%3Ddo-not-execute">Example &amp; page</a>
      <a class="result__snippet">A <b>short</b> snippet</a>
    </div>`;
  const results = parseDuckDuckGoHtml(fixture, 5);
  assert.equal(results.length, 1);
  assert.deepEqual(Object.keys(results[0]).sort(), ['snippet', 'title', 'url']);
  assert.equal(results[0].title, 'Example & page');
  assert.equal(results[0].url, 'https://example.com/page?token=do-not-execute');
  assert.equal(results[0].snippet, 'A short snippet');
});

test('web_fetch extracts HTML and redacts the final URL without live network', async () => {
  const calls = [];
  const tools = new WebTools({
    lookup: publicLookup(),
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return fakeResponse(200, '<html><body><h1>Readable</h1><script>bad()</script><p>Body</p></body></html>', { 'content-type': 'text/html; charset=utf-8' });
    },
  });
  const result = await tools.execute('web_fetch', { url: 'https://example.test/page?token=hidden' });
  assert.equal(result.ok, true);
  assert.equal(result.data.status, 200);
  assert.equal(result.data.contentType, 'text/html; charset=utf-8');
  assert.match(result.data.text, /Readable\nBody/);
  assert.doesNotMatch(result.data.text, /bad/);
  assert.match(result.data.finalUrl, /token=\[REDACTED\]/);
  assert.match(calls[0].options.headers['User-Agent'], /CoderLocally/);
});

test('http_request supports bounded JSON and rejects private redirects', async () => {
  let call = 0;
  const tools = new WebTools({
    lookup: publicLookup(),
    fetchImpl: async () => {
      call += 1;
      if (call === 1) return fakeResponse(302, '', { location: 'http://127.0.0.1/secrets' });
      return fakeResponse(200, '{"hello":"world"}', { 'content-type': 'application/json' });
    },
  });
  const redirected = await tools.execute('web_fetch', { url: 'https://example.test/start' });
  assert.equal(redirected.ok, false);
  assert.match(redirected.error, /private|reserved|allowed/i);

  const jsonTools = new WebTools({
    lookup: publicLookup(),
    fetchImpl: async () => fakeResponse(200, '{"hello":"world"}', { 'content-type': 'application/json' }),
  });
  const result = await jsonTools.execute('http_request', { url: 'https://example.test/api', method: 'POST', body: '{}' });
  assert.equal(result.ok, true);
  assert.match(result.data.text, /"hello": "world"/);
  assert.equal(result.data.truncated, false);
});

test('unsupported URLs and methods return structured failures', async () => {
  const tools = new WebTools({ lookup: publicLookup(), fetchImpl: async () => { throw new Error('must not run'); } });
  const fileResult = await tools.execute('web_fetch', { url: 'file:///C:/secret.txt' });
  assert.equal(fileResult.ok, false);
  assert.equal(typeof fileResult.error, 'string');
  const methodResult = await tools.execute('http_request', { url: 'https://example.test/', method: 'OPTIONS' });
  assert.equal(methodResult.ok, false);
});
