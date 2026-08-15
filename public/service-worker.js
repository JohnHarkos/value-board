// Service worker minimal : met en cache uniquement la coquille de l'app
// (HTML, manifest, icônes) pour qu'elle s'ouvre même hors ligne. Les appels
// à /api/* ne sont JAMAIS mis en cache — les cotes et stats doivent toujours
// être fraîches, jamais servies depuis une copie périmée.
const CACHE_NAME = "value-board-v1";
const ASSETS = ["./", "./index.html", "./manifest.json", "./icon-192.png", "./icon-512.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Round 33 — cause racine trouvée du "piège du cache PWA" documenté à
// répétition dans ce projet (purge manuelle nécessaire à chaque déploiement
// d'un fichier app) : skipWaiting()/clients.claim() ci-dessus étaient déjà
// corrects, mais ne servaient à rien en pratique — CE FICHIER
// (service-worker.js) ne change quasiment jamais d'un déploiement à
// l'autre, seul index.html change. Or un navigateur ne redéclenche tout le
// cycle install/activate (et donc le rechargement de la coquille en
// cache) QUE s'il détecte que service-worker.js a changé, octet pour
// octet. Sans changement de CE fichier précis, aucune mise à jour n'est
// jamais retentée, et la coquille mise en cache au tout premier
// chargement restait donc servie indéfiniment par la stratégie
// "cache d'abord" d'origine — quel que soit le contenu réel déployé sur
// le serveur entre-temps.
//
// Corrigé en passant en "réseau d'abord" (network-first) pour les pages
// HTML (navigations) : la version la plus récente est systématiquement
// demandée au serveur quand une connexion existe, la copie en cache ne
// sert plus que de secours hors ligne — jamais l'inverse. Les autres
// ressources de la coquille (manifest, icônes — qui changent rarement et
// n'ont pas d'enjeu de fraîcheur) restent en "cache d'abord", plus rapide
// et suffisant pour elles. Ce correctif rend la purge manuelle du cache
// inutile pour un déploiement normal — elle reste une solution de secours
// si jamais un problème résiduel apparaissait malgré tout.
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith("/api/")) return; // toujours réseau, jamais de cache

  const isHtmlShell = e.request.mode === "navigate" || url.pathname.endsWith(".html") || url.pathname === "/";
  if (isHtmlShell) {
    e.respondWith(
      fetch(e.request)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(e.request, copy));
          return res;
        })
        .catch(() => caches.match(e.request))
    );
    return;
  }

  e.respondWith(caches.match(e.request).then((cached) => cached || fetch(e.request)));
});
