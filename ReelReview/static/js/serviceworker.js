const CACHE_VERSION = 1;
const CURRENT_CACHE = `main-${CACHE_VERSION}`;

// Routes to be cached
const cacheFiles = [
    "/",
    "static/css/style.css",
    "static/js/app.js",
    "static/js/main.js",
    "static/js/register.js",
    "static/images/favicon.png",
    "static/icons/icon-128x128.png",
    "static/icons/icon-192x192.png",
    "static/icons/icon-384x384.png",
    "static/icons/icon-512x512.png",
];

// Deletes previously registered service workers on activation
self.addEventListener('activate', evt =>
    evt.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CURRENT_CACHE) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    )
);

// Downloads the routes desired to be cached on install
self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(cacheFiles)
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

// Fetches resources from the network
const fromNetwork = (request, timeout) =>
    new Promise((fulfill, reject) => {
        const timeoutId = setTimeout(reject, timeout);
        fetch(request).then(response => {
            clearTimeout(timeoutId);
            fulfill(response);
            update(request);
        }, reject);
    });

// Fetches resources from browser cache when needed
const fromCache = request =>
    caches
        .open(CURRENT_CACHE)
        .then(cache =>
            cache
                .match(request)
                .then(matching => matching || cache.match('/offline/'))
        );

// Cache the currently used page for offline use
const update = request =>
    caches
        .open(CURRENT_CACHE)
        .then(cache =>
            fetch(request).then(response => cache.put(request, response))
        );

// Fetch information from the network, if it can't (offline) fetch from cache
self.addEventListener('fetch', evt => {
    const requestUrl = new URL(evt.request.url);

    // Ignore chrome-extension:// requests
    if (requestUrl.protocol === "chrome-extension:") {
        return;
    }

    evt.respondWith(
        fromNetwork(evt.request, 10000).catch(() => fromCache(evt.request))
    );
    evt.waitUntil(update(evt.request).catch(() => { })); // Ignore caching errors
});