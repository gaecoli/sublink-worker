/**
 * @typedef {Object} KeyValueStore
 * @property {(key: string) => Promise<string | null>} get
 * @property {(key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>} put
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * @typedef {(request: Request) => Promise<Response>} AssetFetcher
 */

/**
 * @typedef {Object} RuntimeConfig
 * @property {number} [configTtlSeconds]
 * @property {number} [shortLinkTtlSeconds]
 * @property {string} [accessToken] - optional shared secret; unset keeps every route open
 */

/**
 * @typedef {Object} RuntimeBindings
 * @property {KeyValueStore | null} [kv]
 * @property {AssetFetcher | null} [assetFetcher]
 * @property {Console} [logger]
 * @property {RuntimeConfig} [config]
 */

const DEFAULTS = {
    configTtlSeconds: 60 * 60 * 24 * 30
};

/**
 * Normalize optional runtime bindings and provide safe defaults.
 *
 * @param {RuntimeBindings | undefined} runtime
 * @returns {{ kv: KeyValueStore | null, assetFetcher: AssetFetcher | null, logger: Console, config: RuntimeConfig & { configTtlSeconds: number, shortLinkTtlSeconds: number | null } }}
 */
// Blank values count as "not configured" so an empty env var never locks the app
function normalizeToken(value) {
    return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export function normalizeRuntime(runtime = {}) {
    return {
        kv: runtime.kv ?? null,
        assetFetcher: runtime.assetFetcher ?? null,
        logger: runtime.logger ?? console,
        config: {
            configTtlSeconds: runtime.config?.configTtlSeconds ?? DEFAULTS.configTtlSeconds,
            shortLinkTtlSeconds: runtime.config?.shortLinkTtlSeconds ?? null,
            accessToken: normalizeToken(runtime.config?.accessToken)
        }
    };
}
