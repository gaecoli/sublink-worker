import { describe, it, expect } from 'vitest';
import { QuanxConfigBuilder } from '../src/builders/QuanxConfigBuilder.js';
import { createApp } from '../src/app/createApp.jsx';
import { MemoryKVAdapter } from '../src/adapters/kv/memoryKv.js';

const UUID = '23ad6b10-8d1a-40f7-8ad0-e3e35cd32291';

const vmessWs = 'vmess://' + btoa(JSON.stringify({
    v: '2', ps: 'HK-vmess', add: 'hk.example.com', port: '443', id: UUID, aid: '0',
    net: 'ws', type: 'none', host: 'hk.example.com', path: '/ws', tls: 'tls', sni: 'hk.example.com'
}));

const INPUT = [
    'ss://' + btoa('aes-256-gcm:pass') + '@1.2.3.4:8388#JP-SS',
    vmessWs,
    `vless://${UUID}@5.6.7.8:443?encryption=none&security=reality&type=tcp&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=0123abcd&flow=xtls-rprx-vision#US-VLESS`,
    'trojan://pwd@tj.example.com:443?sni=tj.example.com#SG,Trojan',
    'anytls://pw@at.example.com:443?sni=at.example.com&insecure=1#JP-AnyTLS',
    'hysteria2://pw@hy.example.com:8443?sni=hy.example.com#US-HY2',
    `vless://${UUID}@g.example.com:443?security=tls&type=grpc&serviceName=x#grpc-node`
].join('\n');

function section(config, name) {
    const match = config.match(new RegExp(`\\[${name}\\]\\n([\\s\\S]*?)(?=\\n\\n\\[|\\n?$)`));
    return match ? match[1].split('\n').filter(Boolean) : [];
}

async function build(input = INPUT, options = {}) {
    const builder = new QuanxConfigBuilder(
        input,
        options.selectedRules ?? 'minimal',
        options.customRules ?? [],
        undefined,
        'en-US',
        'curl/7.74.0',
        options.groupByCountry ?? false
    );
    return builder.build();
}

describe('QuanxConfigBuilder', () => {
    it('converts supported protocols to Quantumult X server lines', async () => {
        const servers = section(await build(), 'server_local');

        expect(servers).toContain('shadowsocks=1.2.3.4:8388, method=aes-256-gcm, password=pass, udp-relay=true, tag=JP-SS');
        expect(servers).toContain(`vmess=hk.example.com:443, method=chacha20-poly1305, password=${UUID}, obfs=wss, obfs-host=hk.example.com, obfs-uri=/ws, tls-verification=true, aead=true, udp-relay=true, tag=HK-vmess`);
        expect(servers).toContain(`vless=5.6.7.8:443, method=none, password=${UUID}, obfs=over-tls, obfs-host=www.apple.com, reality-base64-pubkey=PUBKEY, reality-hex-shortid=0123abcd, vless-flow=xtls-rprx-vision, udp-relay=true, tag=US-VLESS`);
        expect(servers).toContain('trojan=tj.example.com:443, password=pwd, over-tls=true, tls-host=tj.example.com, tls-verification=true, udp-relay=true, tag=SG，Trojan');
        expect(servers).toContain('anytls=at.example.com:443, password=pw, over-tls=true, tls-host=at.example.com, tls-verification=false, udp-relay=true, tag=JP-AnyTLS');
    });

    it('comments out unsupported proxies and keeps them out of policies', async () => {
        const config = await build();
        const servers = section(config, 'server_local');
        const policies = section(config, 'policy');

        expect(servers).toContain('# Unsupported by Quantumult X: US-HY2 - type hysteria2');
        expect(servers).toContain('# Unsupported by Quantumult X: grpc-node - transport grpc');
        expect(policies.join('\n')).not.toContain('US-HY2');
        expect(policies.join('\n')).not.toContain('grpc-node');
    });

    it('refuses values with commas instead of emitting a broken line', async () => {
        const config = await build('ss://' + btoa('aes-256-gcm:pa,ss') + '@1.2.3.4:8388#Bad');
        const servers = section(config, 'server_local');
        expect(servers).toEqual(['# Unsupported by Quantumult X: Bad - password contains a comma or newline']);
    });

    it('emits valid policies referencing existing servers and builtin policies', async () => {
        const config = await build();
        const policies = section(config, 'policy');
        const serverTags = section(config, 'server_local')
            .filter(line => !line.startsWith('#'))
            .map(line => line.split('tag=').pop());
        const policyNames = policies.map(line => line.split('=')[1].split(',')[0].trim());
        const known = new Set([...serverTags, ...policyNames, 'direct', 'reject']);

        expect(policies[0]).toMatch(/^url-latency-benchmark=⚡ Auto Select, .*check-interval=600/);
        policies.forEach(line => {
            expect(line).toMatch(/^(static|url-latency-benchmark)=/);
            const members = line.split(',').slice(1).map(s => s.trim()).filter(s => !s.includes('='));
            members.forEach(member => expect(known.has(member)).toBe(true));
        });
        expect(policies.join('\n')).not.toMatch(/DIRECT|REJECT/);
    });

    it('routes rules through remote lists with the resource parser and ends with final', async () => {
        const config = await build(INPUT, {
            customRules: [{ name: 'MyRule', domain_suffix: 'foo.com', domain_keyword: 'bar', ip_cidr: '1.1.1.0/24,2001:db8::/32', src_ip_cidr: '10.0.0.1/32', site: 'github' }]
        });
        const general = section(config, 'general');
        const remote = section(config, 'filter_remote');
        const local = section(config, 'filter_local');

        expect(general.some(line => line.startsWith('resource_parser_url = https://'))).toBe(true);
        expect(remote[0]).toMatch(/geosite\/github\.conf, tag=geosite:github - MyRule, force-policy=MyRule, update-interval=86400, opt-parser=true, enabled=true$/);
        remote.forEach(line => expect(line).toContain('opt-parser=true'));
        // geosite lists must precede geoip lists
        const firstIp = remote.findIndex(line => line.includes('/geoip/'));
        expect(firstIp).toBeGreaterThan(-1);
        expect(remote.slice(firstIp).every(line => line.includes('/geoip/'))).toBe(true);

        expect(local).toEqual([
            'host-suffix, foo.com, MyRule',
            'host-keyword, bar, MyRule',
            'ip-cidr, 1.1.1.0/24, MyRule',
            'ip6-cidr, 2001:db8::/32, MyRule',
            '# source IP rules are not supported by Quantumult X, skipped: 10.0.0.1/32',
            'final, 🐟 Fall Back'
        ]);
    });

    it('builds country groups and points Node Select at them', async () => {
        const policies = section(await build(INPUT, { groupByCountry: true }), 'policy');
        expect(policies).toContain('url-latency-benchmark=🇯🇵 Japan, JP-SS, JP-AnyTLS, check-interval=600, alive-checking=false, tolerance=0');
        const nodeSelect = policies.find(line => line.startsWith('static=🚀 Node Select'));
        expect(nodeSelect).toContain('🇯🇵 Japan');
        expect(nodeSelect).not.toContain('JP-SS');
    });

    it('deduplicates identical nodes and renames name collisions', async () => {
        const ss = 'ss://' + btoa('aes-256-gcm:pass') + '@1.2.3.4:8388#Same';
        const ss2 = 'ss://' + btoa('aes-256-gcm:other') + '@1.2.3.4:8388#Same';
        const servers = section(await build([ss, ss, ss2].join('\n')), 'server_local');
        expect(servers.map(line => line.split('tag=').pop())).toEqual(['Same', 'Same 2']);
    });

    it('rejects wss nodes whose Host header differs from the TLS SNI', async () => {
        const vmess = 'vmess://' + btoa(JSON.stringify({
            v: '2', ps: 'Mismatch', add: 'a.example.com', port: '443', id: UUID, aid: '0',
            net: 'ws', host: 'cdn.example.com', path: '/ws', tls: 'tls', sni: 'a.example.com'
        }));
        const trojan = 'trojan://pwd@t.example.com:443?sni=t.example.com&type=ws&host=cdn.example.com&path=%2Fws#TJ-Mismatch';
        const config = await build([vmess, trojan].join('\n'));
        expect(section(config, 'server_local')).toEqual([
            '# Unsupported by Quantumult X: Mismatch - ws host differs from tls sni',
            '# Unsupported by Quantumult X: TJ-Mismatch - ws host differs from tls sni'
        ]);
        expect(section(config, 'policy').join('\n')).not.toContain('Mismatch');
    });

    it('keeps untrusted multiline values from injecting config lines', async () => {
        const input = JSON.stringify({
            outbounds: [
                { type: 'shadowsocks', tag: 'BadServer', server: 'a.com\n[mitm]', server_port: 1, method: 'aes-256-gcm', password: 'p' },
                { type: 'shadowsocks', tag: 'BadMethod', server: 'b.com', server_port: 1, method: 'x\n[mitm]\nhostname = *', password: 'p' }
            ]
        });
        const config = await build(input);
        expect(config.match(/^\[mitm\]$/gm)).toHaveLength(1);
        expect(config).not.toMatch(/^hostname/m);
        expect(section(config, 'server_local')).toEqual([
            '# Unsupported by Quantumult X: BadServer - server contains a delimiter',
            '# Unsupported by Quantumult X: BadMethod - cipher x [mitm] hostname = *'
        ]);
    });

    it('reads Sing-Box string plugin_opts', async () => {
        const input = JSON.stringify({
            outbounds: [
                { type: 'shadowsocks', tag: 'V2P', server: 'v.com', server_port: 443, method: 'aes-256-gcm', password: 'p', plugin: 'v2ray-plugin', plugin_opts: 'mode=websocket;tls;host=cdn.example.com;path=/ws' },
                { type: 'shadowsocks', tag: 'OBFS', server: 'o.com', server_port: 443, method: 'aes-256-gcm', password: 'p', plugin: 'obfs-local', plugin_opts: 'obfs=tls;obfs-host=bing.com' }
            ]
        });
        const servers = section(await build(input), 'server_local');
        expect(servers).toEqual([
            'shadowsocks=v.com:443, method=aes-256-gcm, password=p, obfs=wss, obfs-host=cdn.example.com, obfs-uri=/ws, udp-relay=true, tag=V2P',
            'shadowsocks=o.com:443, method=aes-256-gcm, password=p, obfs=tls, obfs-host=bing.com, udp-relay=true, tag=OBFS'
        ]);
    });

    it('treats Clash trojan without a tls key as TLS', async () => {
        const yaml = 'proxies:\n  - {name: CT, type: trojan, server: t.example.com, port: 443, password: p, sni: t.example.com}\n';
        expect(section(await build(yaml), 'server_local')).toEqual([
            'trojan=t.example.com:443, password=p, over-tls=true, tls-host=t.example.com, tls-verification=true, udp-relay=true, tag=CT'
        ]);
    });

    it('references custom rule policies by their literal name', async () => {
        const config = await build(INPUT, {
            customRules: [
                { name: 'Work.Proxy', domain_suffix: 'work.com', site: 'github' },
                { name: 'Google', domain_suffix: 'g.com' }
            ]
        });
        const policies = section(config, 'policy');
        expect(policies.some(line => line.startsWith('static=Work.Proxy, '))).toBe(true);
        expect(section(config, 'filter_local')).toContain('host-suffix, work.com, Work.Proxy');
        expect(section(config, 'filter_local')).toContain('host-suffix, g.com, Google');
        expect(section(config, 'filter_remote')[0]).toContain('force-policy=Work.Proxy,');
    });

    it('drops rules of a nameless custom rule instead of emitting a policy-less line', async () => {
        const config = await build(INPUT, { customRules: [{ name: '', domain_suffix: 'x.com', site: 'github' }] });
        expect(section(config, 'filter_local')).not.toContain('host-suffix, x.com, ');
        section(config, 'filter_local').forEach(line => expect(line).not.toMatch(/,\s*$/));
        expect(section(config, 'filter_remote').join('\n')).not.toContain('github.conf');
    });

    it('never yields an empty policy when no node is supported', async () => {
        const policies = section(await build('hysteria2://pw@hy.example.com:8443#Only-HY2'), 'policy');
        expect(policies).toContain('static=⚡ Auto Select, direct');
    });
});

describe('/quanx route', () => {
    const createTestApp = () => createApp({
        kv: new MemoryKVAdapter(),
        assetFetcher: null,
        logger: console,
        config: { configTtlSeconds: 60, shortLinkTtlSeconds: null }
    });

    it('returns a Quantumult X profile', async () => {
        const app = createTestApp();
        const res = await app.request(`http://localhost/quanx?config=${encodeURIComponent(INPUT)}`);
        expect(res.status).toBe(200);
        const text = await res.text();
        expect(text).toContain('[server_local]');
        expect(text).toContain('tag=JP-SS');
    });

    it('requires the config parameter', async () => {
        const res = await createTestApp().request('http://localhost/quanx');
        expect(res.status).toBe(400);
    });

    it('supports q/ short links', async () => {
        const app = createTestApp();
        const query = `?config=${encodeURIComponent(INPUT)}`;
        const code = await (await app.request(`http://localhost/shorten-v2?url=${encodeURIComponent('http://localhost/quanx' + query)}`)).text();

        const redirect = await app.request(`http://localhost/q/${code}`);
        expect(redirect.status).toBe(302);
        expect(redirect.headers.get('location')).toBe(`http://localhost/quanx${query}`);

        const resolved = await app.request(`http://localhost/resolve?url=${encodeURIComponent(`http://localhost/q/${code}`)}`);
        expect((await resolved.json()).originalUrl).toBe(`http://localhost/quanx${query}`);
    });
});
