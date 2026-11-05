import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/index.js';

const REQUEST = new Request('https://akxst-meta-connector.example.workers.dev/');
const completeConfig = {
  DB: {}, META_APP_ID: 'test-app', META_APP_SECRET: 'test-secret',
  TOKEN_ENCRYPTION_KEY: '1234567890'.repeat(5), ADMIN_EMAIL: 'admin@example.com',
  PUBLIC_BASE_URL: 'https://akxst-meta-connector.example.workers.dev'
};

test('missing configuration fails closed', async () => {
  const response = await worker.fetch(REQUEST, {}, {});
  assert.equal(response.status, 503);
  const body = await response.json();
  assert.match(body.error, /Configuration incomplete/);
});

test('anonymous requests fail closed, even with all secrets configured', async () => {
  const response = await worker.fetch(REQUEST, completeConfig, {});
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.match(body.error, /Access sign-in required/);
});

test('Access-authenticated admin sees callback URI (not token)', async () => {
  const ctx = { access: { getIdentity: async () => ({ email: 'Admin@Example.com' }) } };
  const response = await worker.fetch(new Request('https://akxst-meta-connector.example.workers.dev/api/me'), completeConfig, ctx);
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.email, 'admin@example.com');
  assert.equal(data.isAgencyAdmin, true);
  assert.equal(data.redirectUri, completeConfig.PUBLIC_BASE_URL + '/auth/meta/callback');
  assert.doesNotMatch(JSON.stringify(data), /test-secret/);
});

test('unauthenticated OAuth callback fails before any token exchange', async () => {
  const response = await worker.fetch(new Request('https://akxst-meta-connector.example.workers.dev/auth/meta/callback?code=abc&state=xyz'), completeConfig, {});
  assert.equal(response.status, 403);
});
