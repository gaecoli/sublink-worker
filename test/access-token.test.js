import { describe, it, expect, vi } from 'vitest';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';
import { createCloudflareRuntime } from '../src/runtime/cloudflare.js';

// ioredis cannot load in the workers test pool; the Node runtime test mocks it the same way
vi.mock('ioredis', () => ({ default: class Redis {} }));

const SS = 'ss://' + btoa('aes-256-gcm:pass') + '@1.2.3.4:8388#JP-SS';
const TOKEN = 's3cret-token';

const appWith = (accessToken) => createApp({
    kv: new MemoryKVAdapter(),
    assetFetcher: null,
    logger: { error() {}, warn() {}, info() {} },
    config: { configTtlSeconds: 60, shortLinkTtlSeconds: null, accessToken }
});

const CONVERT_ROUTES = ['singbox', 'clash', 'surge', 'quanx', 'xray'];

describe('ACCESS_TOKEN not set', () => {
    it('leaves every route open, exactly as before', async () => {
        for (const accessToken of [undefined, '', '   ']) {
            const app = appWith(accessToken);
            for (const route of CONVERT_ROUTES) {
                const res = await app.request(`http://localhost/${route}?config=${encodeURIComponent(SS)}`);
                expect(res.status, `${route} with token=${JSON.stringify(accessToken)}`).toBe(200);
            }
            const shorten = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent('http://localhost/clash?config=x')}`);
            expect(shorten.status).toBe(200);
        }
    });

    it('does not render the access token field', async () => {
        const html = await (await appWith(undefined).request('http://localhost/')).text();
        expect(html).not.toContain('id="accessToken"');
        expect(html).toContain('window.APP_ACCESS_REQUIRED = false');
    });
});

describe('ACCESS_TOKEN set', () => {
    it('rejects conversion without or with a wrong token', async () => {
        const app = appWith(TOKEN);
        for (const route of CONVERT_ROUTES) {
            for (const suffix of ['', '&token=wrong', `&token=${TOKEN}x`]) {
                const res = await app.request(`http://localhost/${route}?config=${encodeURIComponent(SS)}${suffix}`);
                expect(res.status, `${route}${suffix}`).toBe(401);
            }
        }
    });

    it('accepts the token as a query parameter or a header', async () => {
        const app = appWith(TOKEN);
        for (const route of CONVERT_ROUTES) {
            const byQuery = await app.request(`http://localhost/${route}?config=${encodeURIComponent(SS)}&token=${TOKEN}`);
            expect(byQuery.status, route).toBe(200);
            const byHeader = await app.request(`http://localhost/${route}?config=${encodeURIComponent(SS)}`, {
                headers: { 'X-Access-Token': TOKEN }
            });
            expect(byHeader.status, route).toBe(200);
        }
    });

    it('protects writes so short links cannot be overwritten', async () => {
        const app = appWith(TOKEN);
        const target = encodeURIComponent(`http://localhost/quanx?config=${encodeURIComponent(SS)}&token=${TOKEN}`);

        const denied = await app.request(`http://localhost/shorten-v2?url=${target}&shortCode=mine`);
        expect(denied.status).toBe(401);

        const created = await app.request(`http://localhost/shorten-v2?url=${target}&shortCode=mine`, { headers: { 'X-Access-Token': TOKEN } });
        expect(await created.text()).toBe('mine');

        const hijack = await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent('http://localhost/quanx?config=evil')}&shortCode=mine`);
        expect(hijack.status).toBe(401);

        const saveConfig = await app.request('http://localhost/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 'quanx', content: '[general]\na = b' })
        });
        expect(saveConfig.status).toBe(401);
    });

    it('keeps short links public and their targets usable by clients', async () => {
        const app = appWith(TOKEN);
        const target = `http://localhost/quanx?config=${encodeURIComponent(SS)}&token=${TOKEN}`;
        await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent(target)}&shortCode=mine`, { headers: { 'X-Access-Token': TOKEN } });

        const redirect = await app.request('http://localhost/q/mine');
        expect(redirect.status).toBe(302);
        const location = redirect.headers.get('location');
        expect(location).toBe(target);

        const followed = await app.request(location);
        expect(followed.status).toBe(200);
        expect(await followed.text()).toContain('tag=JP-SS');
    });

    it('shows the token field but never embeds the token in the page', async () => {
        const html = await (await appWith(TOKEN).request('http://localhost/')).text();
        expect(html).toContain('id="accessToken"');
        expect(html).toContain('window.APP_ACCESS_REQUIRED = true');
        expect(html).not.toContain(TOKEN);
    });
});

describe('runtime wiring', () => {
    it('reads ACCESS_TOKEN from each runtime env', async () => {
        const { createNodeRuntime } = await import('../src/runtime/node.js');
        expect(createNodeRuntime({ ACCESS_TOKEN: TOKEN, DISABLE_MEMORY_KV: 'true' }).config.accessToken).toBe(TOKEN);
        expect(createCloudflareRuntime({ ACCESS_TOKEN: TOKEN }).config.accessToken).toBe(TOKEN);
        expect(createCloudflareRuntime({}).config.accessToken).toBeUndefined();
    });
});
