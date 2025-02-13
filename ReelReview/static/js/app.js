if ("serviceWorker" in navigator) {
    window.addEventListener("load", function () {
        navigator.serviceWorker
            .register("js/serviceworker.js")
            .then((res) => console.log("Service Worker registered:", res))
            .catch((err) => console.log("Service Worker not registered:", err));
    });
}