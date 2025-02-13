const CACHE_VERSION = 1;
const CURRENT_CACHE = `main-${CACHE_VERSION}`;

const cacheFiles = [
    "/",
    "/css/style.css",
    "/js/app.js",
    "/js/main.js",
    "/js/register.js",
    "/images/favicon.png",
    "/icons/icon-128x128.png",
    "/icons/icon-192x192.png",
    "/icons/icon-384x384.png",
    "/icons/icon-512x512.png"
];

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CURRENT_CACHE)
            .then((cache) => {
                console.log("Caching assets during install");
                return cache.addAll(cacheFiles);
            })
            .then(() => self.skipWaiting())
            .catch((e) => {
                console.error("Error during installation:", e);
            })
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CURRENT_CACHE) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request).then(cachedResponse => {
            return cachedResponse || fetch(event.request).catch(() => {
                if (event.request.destination === 'document') {
                    return caches.match('/index.html'); // Offline fallback
                }
            });
        })
    );
});