// Loads the service worker
if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
        navigator.serviceWorker
            .register("../serviceworker.js") // Ensure the path is correct
            .then((res) => console.log("Service Worker registered:", res))
            .catch((err) => console.log("Service Worker not registered:", err));
    });
}