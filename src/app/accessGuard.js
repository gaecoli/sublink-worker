// Optional shared-secret guard. When ACCESS_TOKEN is unset every route behaves as before;
// when set, routes that convert or write must present it (`?token=` or `X-Access-Token`).
// Subscription clients cannot log in interactively, so the token travels in the link itself.

export const ACCESS_TOKEN_HEADER = 'X-Access-Token';

// Constant-time comparison so the response time does not leak how much of a guess matched
function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
}

export function createAccessGuard(accessToken) {
    return async (c, next) => {
        if (!accessToken) return next();
        const provided = c.req.query('token') || c.req.header(ACCESS_TOKEN_HEADER);
        if (!safeEqual(provided, accessToken)) {
            return c.text('Unauthorized: missing or invalid access token', 401);
        }
        return next();
    };
}
