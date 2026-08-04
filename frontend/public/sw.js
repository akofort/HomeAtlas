// HomeAtlas service worker: caches the static app shell (hashed JS/CSS, icons, manifest) so the
// installed PWA still opens offline or on a flaky connection. Never caches anything under /api/ --
// that is live, per-session device/scan/chat state, and caching it would show stale inventory data
// or (worse) leak one signed-in user's response into another session's cache.
const CACHE_VERSION = "homeatlas-v1";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/api/")) return;

  if (request.mode === "navigate") {
    // App shell HTML: always try the network first so a rebuild's new hashed asset references
    // show up immediately on next load; only fall back to whatever shell is cached when genuinely
    // offline.
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match("/"))),
    );
    return;
  }

  // Hashed static assets (JS/CSS under /assets/, icons, the manifest) are content-addressed and
  // immutable -- safe to serve straight from cache once fetched once.
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
        }
        return response;
      });
    }),
  );
});
