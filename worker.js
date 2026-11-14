const SESSION_COOKIE = "portal_session";
const SESSION_LIFETIME_SECONDS = 12 * 60 * 60;
const encoder = new TextEncoder();
const PUBLIC_ASSETS = new Set(["/login.html", "/styles.css"]);

function createResponse(body, status, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

function redirect(location, headers = {}) {
  return createResponse(null, 303, {
    Location: location,
    ...headers,
  });
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie")?.split(";") ?? [];
  const cookie = cookies
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`));

  return cookie?.slice(name.length + 1);
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function signSession(expiresAt, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`portal-session:${expiresAt}`),
  );

  return toBase64Url(new Uint8Array(signature));
}

async function isValidSession(request, secret) {
  const cookie = getCookie(request, SESSION_COOKIE);
  if (!cookie) {
    return false;
  }

  const separator = cookie.indexOf(".");
  if (separator < 1) {
    return false;
  }

  const expiresAt = cookie.slice(0, separator);
  if (!/^\d+$/.test(expiresAt) || Number(expiresAt) <= Math.floor(Date.now() / 1000)) {
    return false;
  }

  const expectedSignature = await signSession(expiresAt, secret);
  const actualSignature = cookie.slice(separator + 1);
  if (actualSignature.length !== expectedSignature.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < expectedSignature.length; index += 1) {
    difference |= expectedSignature.charCodeAt(index) ^ actualSignature.charCodeAt(index);
  }

  return difference === 0;
}

async function passwordsMatch(enteredPassword, configuredPassword) {
  const [enteredHash, configuredHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(enteredPassword)),
    crypto.subtle.digest("SHA-256", encoder.encode(configuredPassword)),
  ]);
  const enteredBytes = new Uint8Array(enteredHash);
  const configuredBytes = new Uint8Array(configuredHash);
  let difference = 0;

  for (let index = 0; index < enteredBytes.length; index += 1) {
    difference |= enteredBytes[index] ^ configuredBytes[index];
  }

  return difference === 0;
}

async function fetchAsset(env, pathname, request) {
  const assetUrl = new URL(pathname, request.url);
  const assetRequest = new Request(assetUrl, request);
  const assetResponse = await env.ASSETS.fetch(assetRequest);
  const headers = new Headers(assetResponse.headers);
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");

  return new Response(assetResponse.body, {
    status: assetResponse.status,
    statusText: assetResponse.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname === "/auth/login") {
      if (request.method !== "POST") {
        return createResponse("Method not allowed", 405, { Allow: "POST" });
      }

      if (
        !env.PORTAL_PASSWORD ||
        env.PORTAL_PASSWORD.length < 12 ||
        !env.SESSION_SECRET ||
        env.SESSION_SECRET.length < 32
      ) {
        return createResponse("Authentication secrets are not configured correctly.", 503);
      }

      const contentType = request.headers.get("Content-Type") ?? "";
      const contentLength = Number(request.headers.get("Content-Length") ?? 0);
      if (
        !contentType.startsWith("application/x-www-form-urlencoded") ||
        !contentLength ||
        contentLength > 4096
      ) {
        return createResponse("Invalid request.", 400);
      }

      const body = await request.text();
      if (encoder.encode(body).byteLength > 4096) {
        return createResponse("Invalid request.", 400);
      }

      const form = new URLSearchParams(body);
      const enteredPassword = form.get("password") ?? "";
      if (!enteredPassword || enteredPassword.length > 1024) {
        return redirect("/login.html?error=1");
      }

      if (!(await passwordsMatch(enteredPassword, env.PORTAL_PASSWORD))) {
        return redirect("/login.html?error=1");
      }

      const expiresAt = String(Math.floor(Date.now() / 1000) + SESSION_LIFETIME_SECONDS);
      const signature = await signSession(expiresAt, env.SESSION_SECRET);

      return redirect("/", {
        "Set-Cookie": `${SESSION_COOKIE}=${expiresAt}.${signature}; Path=/; Max-Age=${SESSION_LIFETIME_SECONDS}; HttpOnly; Secure; SameSite=Strict`,
      });
    }

    if (pathname === "/auth/logout") {
      if (request.method !== "POST") {
        return createResponse("Method not allowed", 405, { Allow: "POST" });
      }

      return redirect("/login.html", {
        "Set-Cookie": `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
      });
    }

    if (PUBLIC_ASSETS.has(pathname)) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return createResponse("Method not allowed", 405, { Allow: "GET, HEAD" });
      }
      return fetchAsset(env, pathname, request);
    }

    if (pathname !== "/" && pathname !== "/index.html") {
      return createResponse("Not found", 404);
    }

    if (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32) {
      return createResponse("Authentication secrets are not configured correctly.", 503);
    }

    if (!(await isValidSession(request, env.SESSION_SECRET))) {
      return redirect("/login.html");
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return createResponse("Method not allowed", 405, { Allow: "GET, HEAD" });
    }

    return fetchAsset(env, "/index.html", request);
  },
};
