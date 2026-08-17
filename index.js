/**
 * VALUE BOARD — SERVEUR RELAIS (Node.js/Express)
 * ----------------------------------------------------
 * Portage du Worker Cloudflare vers un petit serveur Node classique,
 * pour sortir de l'IP de sortie partagée des Workers (qui se faisait
 * bloquer par la protection anti-abus d'API-Football malgré un compte
 * et une clé ayant largement du quota disponible).
 *
 * Différences avec la version Worker :
 * - Cache en mémoire (Map) au lieu du KV Cloudflare — même logique,
 *   vidé si le serveur redémarre, ce qui n'est pas gênant en pratique.
 * - Clés API lues depuis des variables d'environnement (fichier .env)
 *   au lieu des secrets Wrangler.
 * - Un objet "env" est reconstruit à partir de process.env pour que
 *   toute la logique métier ci-dessous reste identique à la version
 *   Worker, sans quasiment rien à réécrire.
 *
 * Routes (identiques à la version Worker) :
 *   GET /api/lookup?home=...&away=...&league=...&season=...&fsCountry=...
 *   GET /api/match?league=ID&season=...&homeId=...&awayId=...
 * ----------------------------------------------------
 */
import express from "express";
import "dotenv/config";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const env = {
  APIFOOTBALL_KEY: process.env.APIFOOTBALL_KEY,
  ODDS_API_KEY: process.env.ODDS_API_KEY,
  ODDSPAPI_API_KEY: process.env.ODDSPAPI_API_KEY,
};

// Clé d'accès partagée : sans elle, n'importe qui trouvant l'IP du serveur
// pourrait consommer le quota API-Football / The Odds API à ta place.
// Doit être définie dans .env (RELAY_KEY=...) et renseignée côté app.
const RELAY_KEY = process.env.RELAY_KEY;

// Round 12 — Sauvegarde serveur du journal. Écrite sur disque (pas juste le
// cache mémoire ci-dessous, vidé à chaque redémarrage) pour que le journal
// (historique des paris, ROI/CLV — le cœur de la valeur produit) survive à
// un changement de navigateur/appareil ou à un passage en navigation privée
// côté client, qui vidait auparavant tout le localStorage.
// Identité = hash de la RELAY_KEY elle-même : cohérent avec le modèle actuel
// à une seule clé partagée, pas besoin d'un vrai système de comptes pour un
// usage perso. Si plusieurs personnes utilisent un jour des clés différentes,
// chacune a naturellement sa propre sauvegarde isolée.
const JOURNAL_DIR = process.env.JOURNAL_DIR || path.join(process.cwd(), "data");
try {
  fs.mkdirSync(JOURNAL_DIR, { recursive: true });
} catch (err) {
  console.error("Impossible de créer JOURNAL_DIR:", err.message);
}
function journalFilePath(key) {
  const id = crypto.createHash("sha256").update(key || "shared").digest("hex").slice(0, 16);
  return path.join(JOURNAL_DIR, "journal-" + id + ".json");
}

const app = express();
// Nécessaire derrière un reverse proxy (Caddy) : sans ça, req.ip renverrait
// toujours l'IP locale de Caddy, et le rate-limiting ci-dessous limiterait
// tout le monde ensemble au lieu de chaque visiteur séparément.
app.set("trust proxy", true);

// Nécessaire pour POST /api/journal-backup (le journal est envoyé dans le
// corps de la requête) — absent avant le Round 12, le serveur ne lisait
// jusque-là que des query params. Limite à 2mb : largement suffisant pour
// un journal de paris personnel, évite qu'une requête malformée ne bloque
// le process.
app.use(express.json({ limit: "2mb" }));

app.use((req, res, next) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  if (req.method === "OPTIONS") return res.status(200).end();
  next();
});

// Rate-limiting en mémoire (même logique que memCache plus bas) : protège
// contre un abus si la clé fuite un jour, ou contre un scanner qui tenterait
// de deviner la clé par force brute — sans ça, une clé compromise pourrait
// vider le quota API-Football / The Odds API en quelques minutes.
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const RATE_LIMIT_MAX = 60; // largement au-dessus d'un usage normal (~15 matchs/session)
const rateLimitMap = new Map(); // ip -> { count, windowStart }
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) rateLimitMap.delete(ip);
  }
}, 60 * 60 * 1000); // purge horaire pour éviter une fuite mémoire lente

app.use((req, res, next) => {
  const ip = req.ip || "unknown";
  const now = Date.now();
  let entry = rateLimitMap.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    rateLimitMap.set(ip, entry);
  }
  entry.count++;
  if (entry.count > RATE_LIMIT_MAX) {
    const retryAfterSec = Math.ceil((entry.windowStart + RATE_LIMIT_WINDOW_MS - now) / 1000);
    res.set("Retry-After", String(retryAfterSec));
    return res.status(429).json({ error: "Trop de requêtes depuis cette adresse IP — réessaie dans quelques minutes." });
  }
  next();
});

app.use((req, res, next) => {
  // Si aucune clé n'est configurée côté serveur, on n'impose rien (permet de
  // tester en local sans se bloquer soi-même) — mais en usage réel, RELAY_KEY
  // doit toujours être défini dans .env.
  if (!RELAY_KEY) return next();
  if (req.query.key === RELAY_KEY) return next();
  res.status(401).json({ error: "Clé d'accès manquante ou invalide (paramètre ?key=...)." });
});

app.get("/api/lookup", async (req, res) => {
  try {
    const params = new URLSearchParams(req.query);
    res.json(await handleLookup(params, env));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.get("/api/match", async (req, res) => {
  try {
    const params = new URLSearchParams(req.query);
    res.json(await handleMatch(params, env));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Round 21 — autocomplete "vivante" : documentée comme faite au Round 9,
// disparue silencieusement (voir STATUS.md), ré-implémentée ici. Contraste
// avec l'autocomplete purement locale déjà présente côté app (qui ne
// mémorise que les noms déjà tapés) : ces deux endpoints interrogent
// API-Football en direct, donc aident aussi sur un nom jamais rencontré
// avant — le cas le plus risqué (c'est une faute de frappe sur un nom
// jamais tapé qui a causé le bug RC Lens/Auxerre avant le Round 13).
// Minimum 3 caractères : évite un appel par lettre tapée, et API-Football
// n'accepte de toute façon pas les recherches plus courtes. Cache 24h
// (par requête texte) : ces listes ne changent pas d'une minute à l'autre.

// Ajoute le 15/08/2026 -- GET /api/journee?sport=soccer_spain_la_liga
// Renvoie tous les matchs a venir d'un championnat avec les cotes de tes
// books (Betclic/Winamax/PMU) et celles de Pinnacle en repere. Une seule
// requete Odds API pour toute la journee, au lieu d'une par match.
app.get("/api/journee", async (req, res) => {
  try {
    const sport = String(req.query.sport || "").trim();
    if (!sport) return res.status(400).json({ error: "parametre 'sport' manquant" });
    res.json(await handleJournee(env, sport));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});
app.get("/api/leagues", async (req, res) => {
  try {
    const query = String(req.query.query || "").trim();
    if (query.length < 3) return res.json({ names: [] });
    res.json(await handleLeagueAutocomplete(env, query));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.get("/api/teams", async (req, res) => {
  try {
    const query = String(req.query.query || "").trim();
    if (query.length < 3) return res.json({ names: [] });
    res.json(await handleTeamAutocomplete(env, query));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Ajouté le 14/08/2026 — GET /api/league-teams?league=...&season=...
// Renvoie la liste des équipes d'un championnat donné, pour restreindre
// les champs domicile/extérieur côté app une fois le championnat choisi.
app.get("/api/league-teams", async (req, res) => {
  try {
    const league = String(req.query.league || "").trim();
    const season = String(req.query.season || "").trim() || String(new Date().getFullYear());
    const leagueId = String(req.query.leagueId || "").trim();
    if (!league) return res.status(400).json({ error: "Paramètre 'league' manquant." });
    res.json(await handleLeagueTeams(env, league, season, leagueId));
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

// Round 12 — Sauvegarde/restauration du journal (historique des paris,
// réglages). Volontairement minimaliste : un seul fichier par clé
// d'accès, pas d'historique de versions ni de fusion — la dernière
// sauvegarde écrase la précédente, comme un export/import classique
// mais automatique et sans manipulation de fichier.
app.post("/api/journal-backup", (req, res) => {
  try {
    const body = req.body || {};
    if (!body || typeof body !== "object" || !Array.isArray(body.bets)) {
      return res.status(400).json({ error: "Corps invalide : { cfg, bets } attendu, bets doit être un tableau." });
    }
    const payload = {
      cfg: body.cfg || {},
      bets: body.bets,
      savedAt: new Date().toISOString(),
    };
    fs.writeFileSync(journalFilePath(req.query.key), JSON.stringify(payload), "utf8");
    res.json({ ok: true, savedAt: payload.savedAt });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.get("/api/journal-backup", (req, res) => {
  try {
    const file = journalFilePath(req.query.key);
    if (!fs.existsSync(file)) {
      return res.status(404).json({ error: "Aucune sauvegarde trouvée sur le serveur pour cette clé." });
    }
    const data = JSON.parse(fs.readFileSync(file, "utf8"));
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Route inconnue. Utilise /api/lookup ou /api/match" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Value Board relais démarré sur le port " + PORT));

const norm = s => (s || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]/g, "");

// Correctif (14/08/2026) : API-Football refuse tout caractère non
// alphanumérique/espace dans le paramètre "search" ("Vitória" -> 400,
// "The Search field may only contain alpha-numeric characters and
// spaces."). norm() ci-dessus est trop agressif pour ça (retire aussi les
// espaces, casse la casse) — on veut juste retirer les accents, garder le
// reste identique ("Vitória SC" -> "Vitoria SC").
const stripDiacritics = s => (s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "");

// Timeout sur tous les appels externes (API-Football, The Odds API,
// Understat, football-data.co.uk) : sans ça, une source qui ne
// répond jamais bloquerait "Chercher automatiquement" indéfiniment, sans
// jamais échouer proprement côté app.
const FETCH_TIMEOUT_MS = 15000;
async function fetchT(url, opts = {}) {
  return fetch(url, { ...opts, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
}



/* =====================================================
   /api/lookup
   ===================================================== */
async function handleLookup(params, env) {
  const homeName = params.get("home");
  const awayName = params.get("away");
  const leagueName = params.get("league");
  const season = params.get("season") || String(new Date().getFullYear());
  let fsCountry = params.get("fsCountry"); // ex: "Sweden" — sert la vraie moyenne du championnat (football-data.co.uk)

  const missing = ["home", "away", "league"].filter(k => !params.get(k));
  if (missing.length) throw new Error("Paramètres manquants: " + missing.join(", "));

  const warnings = [];

  // Round 19 — jusqu'ici, la vraie moyenne du championnat (football-data.co.uk,
  // plus fiable que l'estimation via le classement API-Football, notamment
  // en tout début de saison) exigeait de taper le pays à la main dans un
  // champ optionnel que presque personne ne remplissait — la moyenne
  // retombait donc systématiquement sur l'approximation via /standings.
  // On la déduit maintenant automatiquement à partir du pays du championnat
  // résolu par API-Football, SAUF si la personne a explicitement rempli le
  // champ Pays elle-même (son choix reste toujours prioritaire).
  // Best-effort et non bloquant : si cette résolution échoue ici, on la
  // retente normalement dans le bloc stats ci-dessous (avec son warning
  // habituel) — cet essai ne sert qu'à deviner le pays, ce n'est pas une
  // dépendance dure pour le reste du calcul.
  if (!fsCountry) {
    try {
      const probe = await resolveLeague(env, leagueName, season);
      if (probe.country && isKnownFDCountry(probe.country)) fsCountry = probe.country;
    } catch (err) {
      // ignoré : pas grave, resolveLeague sera retentée normalement plus bas
    }
  }

  // Les 4 sources (stats, xG, cotes, moyenne championnat) interrogent des API
  // totalement indépendantes, avec des limites de débit différentes — les
  // lancer en parallèle plutôt qu'en série divise le temps d'attente total,
  // sans changer le résultat. Seul l'intérieur du bloc stats reste
  // séquentiel (ligue → équipes → stats), parce que ces trois appels-là
  // partagent bien la même limite API-Football.
  const [statsResult, xgResult, oddsResult, avgResult] = await Promise.allSettled([
    (async () => {
      const league = await resolveLeague(env, leagueName, season);
      const homeTeam = await resolveTeam(env, homeName, league.leagueId, season);
      const awayTeam = await resolveTeam(env, awayName, league.leagueId, season);
      const stats = await getGoalStats(env, league.leagueId, season, homeTeam.id, awayTeam.id);
      // Round 22, corrigé lors de l'audit du 30/07/2026 — best-effort total :
      // jamais bloquant, jamais retenté, une erreur ici ne doit surtout pas
      // faire échouer le calcul de stats déjà obtenu. Deux corrections
      // depuis la version initiale de ce round :
      // 1) on utilise la saison EFFECTIVEMENT utilisée par chaque équipe
      //    (stats.homeSeasonUsed/awaySeasonUsed, qui reflète le repli du
      //    Round 16 si celui-ci s'est déclenché), pas la saison brute
      //    demandée — sinon les blessures interrogeraient une saison pas
      //    encore commencée sur les matchs qui déclenchent justement ce repli.
      // 2) les deux appels (domicile/extérieur) sont lancés en parallèle,
      //    pas en série comme le reste des appels API-Football de ce
      //    fichier — contrairement à resolveTeam/getGoalStats, aucune
      //    contrainte de rate-limit connue ne justifie de les sérialiser
      //    ici, et ça évite d'ajouter encore 1+ seconde incompressible à
      //    une recherche déjà lente sur un match jamais vu.
      // 3) on construit un nouvel objet plutôt que de modifier "stats" en
      //    place, qui est le même objet que celui déjà stocké dans le
      //    cache mémoire de getGoalStats (1h) — le modifier directement
      //    aurait fonctionné par coïncidence mais créait un couplage caché
      //    fragile entre ce cache et cet ajout.
      try {
        const [homeInjuries, awayInjuries] = await Promise.all([
          getTeamInjuries(env, league.leagueId, stats.homeSeasonUsed, homeTeam.id),
          getTeamInjuries(env, league.leagueId, stats.awaySeasonUsed, awayTeam.id),
        ]);
        if (homeInjuries.length || awayInjuries.length) {
          return { ...stats, injuries: { home: homeInjuries, away: awayInjuries } };
        }
      } catch (err) {
        // best-effort : absence d'info sur les blessures, pas une erreur à signaler
      }
      return stats;
    })(),
    (async () => {
      const slug = understatSlugFor(leagueName);
      return await getXGViaLeague(slug, season, homeName, awayName);
    })(),
    (async () => {
      const sportKey = await resolveSportKey(env, leagueName);
      return await getOddsCached(env, sportKey, homeName, awayName);
    })(),
    fsCountry ? getLeagueAverages(leagueName, fsCountry, season) : Promise.resolve(null),
  ]);

  let statsPart = null, xgPart = null, oddsPart = null;

  if (statsResult.status === "fulfilled") {
    statsPart = statsResult.value;
    if (statsPart?.warnings?.length) warnings.push(...statsPart.warnings);
  }
  else warnings.push("stats (API-Football): " + statsResult.reason.message);

  if (xgResult.status === "fulfilled") {
    xgPart = xgResult.value;
    if (xgPart?.warnings?.length) warnings.push(...xgPart.warnings);
  }
  else warnings.push("xG (Understat): " + xgResult.reason.message);

  if (oddsResult.status === "fulfilled") {
    oddsPart = oddsResult.value.odds;
    if (oddsResult.value.warning) warnings.push(oddsResult.value.warning);
  } else {
    warnings.push("cotes (The Odds API): " + oddsResult.reason.message);
  }

  if (fsCountry) {
    if (avgResult.status === "fulfilled" && avgResult.value) {
      if (!statsPart) statsPart = {};
      statsPart.lgH = avgResult.value.lgH;
      statsPart.lgA = avgResult.value.lgA;
      if (avgResult.value.seasonUsed) warnings.push("repli sur la saison " + avgResult.value.seasonUsed + " pour la moyenne du championnat (aucun match joue en " + season + ")");
    } else if (avgResult.status === "rejected") {
      warnings.push("moyenne championnat (football-data.co.uk): " + avgResult.reason.message);
    }
  }

  return {
    homeName, awayName, league: leagueName, season,
    values: buildValues(statsPart, xgPart, oddsPart),
    oddsSpread: oddsPart?.spread || null,
    pinnacle: oddsPart?.pinnacle || null, // {marché: {spread, count}} — dispersion entre bookmakers
    oddsBestBook: oddsPart?.bestBook || null, // {marché: nom du bookmaker offrant la meilleure cote}
    injuries: statsPart?.injuries || null, // Round 22 — {home: [...], away: [...]}, purement informatif
    importCode: buildImportCode(homeName, awayName, statsPart, xgPart, oddsPart),
    warnings,
  };
}

/* =====================================================
   /api/match — inchangé (IDs déjà connus)
   ===================================================== */
async function handleMatch(params, env) {
  const league = params.get("league");
  const season = params.get("season");
  const homeId = params.get("homeId");
  const awayId = params.get("awayId");
  const homeName = params.get("homeName");
  const awayName = params.get("awayName");
  const sportKey = params.get("sport");
  const leagueName = params.get("leagueName") || homeName;
  let fsCountry = params.get("fsCountry");

  const missing = ["league", "season", "homeId", "awayId", "homeName", "awayName"]
    .filter(k => !params.get(k));
  if (missing.length) throw new Error("Paramètres manquants: " + missing.join(", "));

  const warnings = [];

  // Round 19 — même auto-détection que dans handleLookup, mais ici on part
  // d'un ID de ligue déjà connu (pas d'un nom libre) puisque /api/match sert
  // le Scan, où les IDs sont déjà résolus. getLeagueCountry résout le pays
  // à partir de cet ID directement, avec son propre cache (30 jours).
  if (!fsCountry) {
    try {
      const country = await getLeagueCountry(env, league);
      if (country && isKnownFDCountry(country)) fsCountry = country;
    } catch (err) {
      // ignoré : best-effort, ne bloque jamais le reste du calcul
    }
  }

  // Même parallélisation que handleLookup : ces 4 sources n'ont aucune
  // dépendance entre elles ici (les IDs sont déjà connus), donc aucune
  // raison de les attendre en série.
  const [statsResult, xgResult, oddsResult, avgResult] = await Promise.allSettled([
    (async () => {
      const stats = await getGoalStats(env, league, season, homeId, awayId);
      // Mêmes trois correctifs que dans handleLookup (voir ses commentaires
      // détaillés) : bonne saison de repli, appels parallèles, pas de
      // mutation de l'objet mis en cache par getGoalStats.
      try {
        const [homeInjuries, awayInjuries] = await Promise.all([
          getTeamInjuries(env, league, stats.homeSeasonUsed, homeId),
          getTeamInjuries(env, league, stats.awaySeasonUsed, awayId),
        ]);
        if (homeInjuries.length || awayInjuries.length) {
          return { ...stats, injuries: { home: homeInjuries, away: awayInjuries } };
        }
      } catch (err) {
        // best-effort : absence d'info sur les blessures, pas une erreur à signaler
      }
      return stats;
    })(),
    (async () => {
      const slug = understatSlugFor(leagueName);
      return await getXGViaLeague(slug, season, homeName, awayName);
    })(),
    sportKey ? getOddsCached(env, sportKey, homeName, awayName) : Promise.reject(new Error("paramètre 'sport' non fourni")),
    fsCountry ? getLeagueAverages(leagueName, fsCountry, season) : Promise.resolve(null),
  ]);

  let statsPart = null, xgPart = null, oddsPart = null;

  if (statsResult.status === "fulfilled") {
    statsPart = statsResult.value;
    if (statsPart?.warnings?.length) warnings.push(...statsPart.warnings);
  }
  else warnings.push("stats (API-Football): " + statsResult.reason.message);

  if (xgResult.status === "fulfilled") {
    xgPart = xgResult.value;
    if (xgPart?.warnings?.length) warnings.push(...xgPart.warnings);
  }
  else warnings.push("xG (Understat): " + xgResult.reason.message);

  if (oddsResult.status === "fulfilled") {
    oddsPart = oddsResult.value.odds;
    if (oddsResult.value.warning) warnings.push(oddsResult.value.warning);
  } else {
    warnings.push("cotes: " + (sportKey ? "The Odds API: " + oddsResult.reason.message : oddsResult.reason.message));
  }

  if (fsCountry) {
    if (avgResult.status === "fulfilled" && avgResult.value) {
      if (!statsPart) statsPart = {};
      statsPart.lgH = avgResult.value.lgH;
      statsPart.lgA = avgResult.value.lgA;
      if (avgResult.value.seasonUsed) warnings.push("repli sur la saison " + avgResult.value.seasonUsed + " pour la moyenne du championnat (aucun match joue en " + season + ")");
    } else if (avgResult.status === "rejected") {
      warnings.push("moyenne championnat (football-data.co.uk): " + avgResult.reason.message);
    }
  }

  return {
    homeName, awayName,
    values: buildValues(statsPart, xgPart, oddsPart),
    oddsSpread: oddsPart?.spread || null,
    pinnacle: oddsPart?.pinnacle || null,
    oddsBestBook: oddsPart?.bestBook || null,
    injuries: statsPart?.injuries || null, // Round 22
    importCode: buildImportCode(homeName, awayName, statsPart, xgPart, oddsPart),
    warnings,
  };
}

function buildValues(stats, xg, odds) {
  return {
    a1: stats?.a1 ?? null, a2: stats?.a2 ?? null, a3: stats?.a3 ?? null, a4: stats?.a4 ?? null,
    b1: xg?.b1 ?? null, b2: xg?.b2 ?? null, b3: xg?.b3 ?? null, b4: xg?.b4 ?? null,
    lgH: stats?.lgH ?? null, lgA: stats?.lgA ?? null,
    nH: stats?.nH ?? null, nA: stats?.nA ?? null,
    o1: odds?.o1 ?? null, oX: odds?.oX ?? null, o2: odds?.o2 ?? null,
    oBTTSyes: odds?.oBTTSyes ?? null, oBTTSno: odds?.oBTTSno ?? null,
    oO25: odds?.oO25 ?? null, oU25: odds?.oU25 ?? null,
    oO15: odds?.oO15 ?? null, oU15: odds?.oU15 ?? null,
  };
}

function buildImportCode(homeName, awayName, stats, xg, odds) {
  // Correctif (14/08/2026) : un champ manquant (source en échec, ex. xG
  // non couvert par Understat) tombait sur "0.00" — un lambda basé sur 0
  // s'effondre artificiellement (shrink(0,n) très bas), ce qui pouvait
  // fabriquer une fausse "value" sur les marchés under. On retombe
  // maintenant sur la moyenne du championnat (lgH/lgA) comme valeur
  // neutre — la même logique que le moteur utilise déjà par défaut côté
  // app (setA/setB, Round 20) — jamais un signal fabriqué à partir de rien.
  // Mapping (identique à lambdasFrom côté app) : gfH/gaA se comparent à
  // lgH, gfA/gaH se comparent à lgA — donc a1/a4/b1/b4 -> lgH,
  // a2/a3/b2/b3 -> lgA.
  const DEFAULT_LGH = 1.45, DEFAULT_LGA = 1.15;
  const lgH = (stats?.lgH != null && isFinite(stats.lgH)) ? stats.lgH : DEFAULT_LGH;
  const lgA = (stats?.lgA != null && isFinite(stats.lgA)) ? stats.lgA : DEFAULT_LGA;
  const n = (v, fallback, d = 2) => (v === null || v === undefined || isNaN(v)) ? fallback.toFixed(d) : Number(v).toFixed(d);
  return [
    homeName, awayName,
    [n(stats?.a1, lgH), n(stats?.a2, lgA), n(stats?.a3, lgA), n(stats?.a4, lgH)].join("/"),
    [n(xg?.b1, lgH), n(xg?.b2, lgA), n(xg?.b3, lgA), n(xg?.b4, lgH)].join("/"),
    [n(stats?.lgH, DEFAULT_LGH), n(stats?.lgA, DEFAULT_LGA)].join("/"),
    [stats?.nH ?? 0, stats?.nA ?? 0].join("/"),
    [n(odds?.o1, 0), n(odds?.oX, 0), n(odds?.o2, 0)].join("/"),
    [n(odds?.oBTTSyes, 0), n(odds?.oBTTSno, 0)].join("/"),
    [n(odds?.oO25, 0), n(odds?.oU25, 0)].join("/"),
    [n(odds?.oO15, 0), n(odds?.oU15, 0)].join("/"),
  ].join("|");
}

// Round 21 — autocomplete vivante (voir les routes /api/leagues et
// /api/teams plus haut). Cache 24h par texte tapé, dédoublonnage des noms
// (API-Football peut renvoyer plusieurs entrées pour un même nom de club
// dans des divisions différentes), limité à 15 résultats — largement
// suffisant pour une liste déroulante, évite d'alourdir la réponse.
async function handleLeagueAutocomplete(env, query) {
  const cacheKey = "leagueautocomplete2:" + norm(query);
  const cached = await cacheGet(env, cacheKey);
  if (cached) return { results: cached, names: cached.map(r => r.name) };
  const res = await apiFootballGet(env, "/leagues", { search: query });
  const seen = new Set();
  const results = [];
  for (const r of (res || [])) {
    const name = r.league?.name;
    if (!name || seen.has(name + "|" + r.league?.id)) continue;
    seen.add(name + "|" + r.league?.id);
    results.push({ id: r.league?.id, name, country: r.country?.name || "" });
    if (results.length >= 15) break;
  }
  await cacheSet(env, cacheKey, results, 86400); // 24h
  return { results, names: results.map(r => r.name) };
}

async function handleTeamAutocomplete(env, query) {
  const cacheKey = "teamautocomplete:" + norm(query);
  const cached = await cacheGet(env, cacheKey);
  if (cached) return { names: cached };
  const res = await apiFootballGet(env, "/teams", { search: query });
  const names = Array.from(new Set((res || []).map(r => r.team?.name).filter(Boolean))).slice(0, 15);
  await cacheSet(env, cacheKey, names, 86400); // 24h
  return { names };
}

// Ajouté le 14/08/2026 — liste complète des équipes d'un championnat/saison,
// pour que l'app puisse restreindre les champs domicile/extérieur une fois
// le championnat choisi, plutôt qu'une recherche mondiale sur un nom libre
// (source des erreurs "nom ambigu" / accents rejetés par API-Football).
// Si leagueId est fourni (cas normal depuis la sélection dans la liste
// déroulante), on saute complètement resolveLeague — aucune ambiguïté
// possible, aucun appel réseau supplémentaire. leagueId reste optionnel
// (repli sur resolveLeague par nom) pour ne pas casser un appel plus ancien.
async function handleLeagueTeams(env, leagueName, season, leagueId) {
  let league;
  if (leagueId) {
    league = { leagueId: Number(leagueId), name: leagueName };
  } else {
    league = await resolveLeague(env, leagueName, season);
  }
  const cacheKey = "leagueteamslist:" + league.leagueId + ":" + season;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return { names: cached, league: league.name };
  const res = await apiFootballGet(env, "/teams", { league: league.leagueId, season });
  const names = Array.from(new Set((res || []).map(r => r.team?.name).filter(Boolean))).sort((a, b) => a.localeCompare(b));
  await cacheSet(env, cacheKey, names, 604800); // 7 jours — composition de ligue stable en cours de saison
  return { names, league: league.name };
}

/* =====================================================
   API-FOOTBALL (inchangé)
   ===================================================== */
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---- Cache mémoire : réduit le NOMBRE d'appels API-Football, pas juste
// leur rythme. C'est ça qui règle le rate limit, pas le sleep() ci-dessous.
// Contrairement à la version Cloudflare Worker (KV), ici le cache vit en
// mémoire du process Node — il est vidé si le serveur redémarre, mais ça
// n'est pas un problème : les infos importantes (ligue/équipe) se
// re-remplissent au premier lookup suivant.
const memCache = new Map(); // key -> { value, expiresAt }
// Purge périodique : sans ça, une clé jamais re-consultée (ex. une ligue ou
// une équipe demandée une seule fois) reste en mémoire indéfiniment même
// après expiration — fuite mémoire lente sur un serveur qui tourne des mois.
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of memCache) {
    if (now > entry.expiresAt) memCache.delete(key);
  }
}, 60 * 60 * 1000); // purge horaire, même rythme que celle du rate-limiting
async function cacheGet(env, key) {
  const entry = memCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { memCache.delete(key); return null; }
  return entry.value;
}
async function cacheSet(env, key, value, ttlSeconds) {
  memCache.set(key, { value, expiresAt: Date.now() + ttlSeconds * 1000 });
}


async function apiFootballGet(env, path, qs) {
  // Pause avant chaque appel : filet de sécurité en plus du cache ci-dessus,
  // pour les appels qui ne peuvent pas être évités (premier lookup d'une
  // équipe/ligue jamais vue).
  await sleep(1100);
  // Correctif (14/08/2026) : le paramètre "search" plante avec un accent
  // ("Vitória" -> 400 côté API-Football). On le nettoie ici, au point
  // d'entrée unique de tous les appels API-Football, plutôt que dans
  // chaque fonction appelante — corrige le problème pour toutes les
  // équipes/ligues accentuées d'un coup (Málaga, Deportivo La Coruña,
  // İstanbul Başakşehir...), pas seulement Vitória.
  if (qs && typeof qs.search === "string") qs = { ...qs, search: stripDiacritics(qs.search) };
  const url = "https://v3.football.api-sports.io" + path + "?" + new URLSearchParams(qs);

  // Nouvelle tentative automatique sur rate limit : confirmé par test direct
  // (curl depuis un poste normal) que la clé et le compte ont largement du
  // quota disponible (299/300 par minute, 7439/7500 par jour) — le blocage
  // vient donc de l'IP de sortie partagée des Workers Cloudflare, pas de la
  // clé elle-même. C'est un phénomène de bruit externe, temporaire par
  // nature, donc une nouvelle tentative avec pause a de bonnes chances de
  // passer sans jamais avoir touché à la clé ou au compte.
  const MAX_ATTEMPTS = 3;
  let lastErr = null;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const res = await fetchT(url, {
      headers: { "x-apisports-key": env.APIFOOTBALL_KEY },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      lastErr = new Error("API-Football HTTP " + res.status + " sur " + path + " — " + body.slice(0, 200));
      // Un vrai code HTTP d'échec (401, 500...) ne se règle pas en réessayant
      // dans la seconde — pas la peine d'attendre, on sort tout de suite.
      throw lastErr;
    }
    const data = await res.json();
    const isRateLimit = data.errors && Object.keys(data.errors).some(k =>
      /ratelimit/i.test(k) || /too many requests/i.test(String(data.errors[k])));
    if (data.errors && Object.keys(data.errors).length && !isRateLimit) {
      throw new Error("API-Football (" + path + "): " + JSON.stringify(data.errors));
    }
    if (isRateLimit) {
      lastErr = new Error("API-Football (" + path + "): " + JSON.stringify(data.errors));
      if (attempt < MAX_ATTEMPTS) {
        await sleep(2000 * attempt); // 2s, puis 4s avant les tentatives suivantes
        continue;
      }
      throw lastErr;
    }
    return data.response;
  }
  throw lastErr;
}

async function resolveLeague(env, leagueName, season) {
  // L'ID d'une ligue ne change jamais — cache long (30 jours). C'est le
  // premier appel de la chaîne, donc le premier gain, et le plus rentable
  // puisqu'il est identique pour tous les utilisateurs qui tapent "liga mx".
  const cacheKey = "league:" + norm(leagueName);
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const res = await apiFootballGet(env, "/leagues", { search: leagueName });
  if (!res || !res.length) throw new Error("championnat introuvable: " + leagueName);

  // La recherche peut renvoyer plusieurs entrées proches (ex. "Liga MX"
  // ET "Liga MX Femenil"). On priorise : nom exact > type "League"
  // (pas Cup) > présence de la saison demandée.
  const n = norm(leagueName);
  const score = r => {
    let s = 0;
    if (norm(r.league.name) === n) s += 100;
    if (r.league.type === "League") s += 10;
    if ((r.seasons || []).some(x => String(x.year) === String(season))) s += 1;
    return s;
  };
  const entry = res.slice().sort((a, b) => score(b) - score(a))[0];
  const out = { leagueId: entry.league.id, name: entry.league.name, country: entry.country?.name };
  await cacheSet(env, cacheKey, out, 2592000); // 30 jours
  return out;
}

async function getLeagueTeamIds(env, leagueId, season) {
  // Liste des équipes réellement inscrites dans cette ligue/saison — sert
  // à vérifier qu'un nom trouvé par recherche libre (resolveTeam) est bien
  // le bon "Tigres"/"Racing"/etc., et pas un homonyme d'un autre pays.
  // Cache 7 jours : une composition de ligue ne change pas en cours de saison.
  const cacheKey = "leagueteams:" + leagueId + ":" + season;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return new Set(cached);
  const res = await apiFootballGet(env, "/teams", { league: leagueId, season });
  const ids = (res || []).map(r => r.team.id);
  await cacheSet(env, cacheKey, ids, 604800); // 7 jours
  return new Set(ids);
}

async function resolveTeam(env, teamName, leagueId, season) {
  // Cache incluant ligue+saison : le même nom ("Tigres") doit pouvoir
  // désigner des équipes différentes selon le championnat — l'ancien cache
  // "team:tigres" tout court était justement la source du bug (un homonyme
  // sans lien avec la Liga MX pouvait être renvoyé et mis en cache pour tous).
  const cacheKey = "team:" + norm(teamName) + ":" + leagueId + ":" + season;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  // L'API-Football refuse de combiner "search" avec "league"/"season" —
  // on cherche par nom seul, puis on restreint aux équipes confirmées dans
  // CETTE ligue/saison (getLeagueTeamIds) avant de trancher par proximité
  // de nom. Sans cette vérification, un nom ambigu (ex. "Tigres" existe
  // dans plusieurs pays) peut faire remonter une équipe qui n'a joué aucun
  // match dans le bon championnat — stats à 0.00 partout, value faussée.
  const res = await apiFootballGet(env, "/teams", { search: teamName });
  if (!res || !res.length) throw new Error("équipe introuvable: " + teamName);

  let candidates = res;
  try {
    const validIds = await getLeagueTeamIds(env, leagueId, season);
    if (validIds.size) {
      const inLeague = res.filter(r => validIds.has(r.team.id));
      if (!inLeague.length) {
        throw new Error("'" + teamName + "' introuvable dans cette ligue/saison — " +
          "nom probablement ambigu (un homonyme existe dans un autre pays). " +
          "Essaie un nom plus complet (ex. \"Tigres UANL\" plutôt que \"Tigres\").");
      }
      candidates = inLeague;
    }
  } catch (err) {
    if (err.message.includes("introuvable dans cette ligue")) throw err;
    // si la vérification elle-même échoue (ex. API indisponible), on retombe
    // sur l'ancien comportement best-effort plutôt que de tout bloquer.
  }

  const n = norm(teamName);
  const best = candidates.slice().sort((a, b) => {
    const an = norm(a.team.name), bn = norm(b.team.name);
    const score = x => x === n ? 100 : (x.includes(n) || n.includes(x) ? 10 : 0);
    return score(bn) - score(an);
  })[0];
  await cacheSet(env, cacheKey, best.team, 2592000); // 30 jours
  return best.team;
}

// Round 15 (pondération récente), affiné au Round 18 — un match de la 1ère
// journée ne devrait pas peser autant qu'un match de la semaine dernière
// dans l'évaluation de la forme actuelle d'une équipe (nouvel entraîneur,
// blessures, forme du moment...). S'applique aux deux lectures (buts réels
// ET xG) puisque les deux disposent d'un historique match par match une
// fois récupéré.
//
// Round 18 — le Round 15 utilisait un seuil fixe (les 6 matchs les plus
// récents comptent double, le reste compte 1) : un effet de palier
// arbitraire entre le 6ème et le 7ème match les plus récents, sans lien
// avec l'écart de temps réel entre les matchs. Remplacé ici par une
// décroissance exponentielle continue selon le nombre de jours écoulés
// depuis chaque match : plus un match est ancien, plus son poids diminue
// progressivement, sans palier brutal. HALF_LIFE_DAYS=60 signifie qu'un
// match vieux de 60 jours pèse deux fois moins qu'un match d'aujourd'hui,
// un match vieux de 120 jours pèse quatre fois moins, etc. — une valeur
// empirique raisonnable pour une saison de football (~9-10 mois), à
// ajuster si l'expérience montre qu'elle sur- ou sous-pondère la forme
// récente.
/* ---------- pondération temporelle : DÉBUT (fonction pure, testée
   automatiquement, voir tests/decay.test.js) ---------- */
const HALF_LIFE_DAYS = 270; // etait 60. Mesure sur 9586 predictions, 8 championnats, 2 paires de saisons : Brier 0.6021 (60j) -> 0.5939 (270j). A 60 jours, un match de la saison passee pesait 1.5% d un match recent, ce qui annulait le melange des deux saisons. Plateau plat entre 270 et 365 j ; 270 retenu pour rester un peu plus reactif.
const DECAY_RATE = Math.log(2) / HALF_LIFE_DAYS;

function weightedRecentAverage(rows, dateOf, valueOf, referenceDate) {
  referenceDate = referenceDate || new Date();
  let sumW = 0, sumWV = 0;
  rows.forEach(r => {
    const v = valueOf(r);
    if (v === null || v === undefined || isNaN(v)) return;
    const matchDate = new Date(dateOf(r));
    if (isNaN(matchDate.getTime())) return; // date invalide/absente — ce match n'entre pas dans le calcul
    const daysAgo = Math.max(0, (referenceDate - matchDate) / 86400000);
    const w = Math.exp(-DECAY_RATE * daysAgo);
    sumW += w;
    sumWV += w * v;
  });
  return sumW ? sumWV / sumW : null;
}
/* ---------- pondération temporelle : FIN ---------- */

async function getRecentFixtures(env, leagueId, season, teamId) {
  // Cache 1h : même logique que getGoalStats — les matchs joués ne
  // changent qu'à la fin de chaque journée, pas la peine de re-taper l'API
  // à chaque recherche dans l'heure.
  const cacheKey = "fixtures:" + leagueId + ":" + season + ":" + teamId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  const res = await apiFootballGet(env, "/fixtures", { league: leagueId, season, team: teamId, status: "FT" });
  const fixtures = res || [];
  await cacheSet(env, cacheKey, fixtures, 3600);
  return fixtures;
}

async function getTeamStatsForSeason(env, league, season, teamId) {
  return await apiFootballGet(env, "/teams/statistics", { league, season, team: teamId });
}


// Melange des deux saisons. Mesure par backtest sur 8 premieres journees,
// 8 championnats, 2 paires de saisons :
//   sans melange (comportement precedent) : Brier 0.6166 sur 240 matchs
//   poids 1 : 0.5883   poids 2 : 0.5840   poids 3 : 0.5894   poids 5 : 0.5939
// Poids 2 retenu : un match de la saison en cours compte comme deux de la
// precedente. Gain de 0.033 sur le Brier (l optimisation de K et rho n en
// rapportait que 0.0002) et 4x plus de matchs analysables en debut de saison.
const POIDS_SAISON_COURANTE = 2;

function melangeStats(sNew, sOld) {
  const nNew = sNew?.fixtures?.played;
  const nOld = sOld?.fixtures?.played;
  if (!nOld || (nOld.home + nOld.away) === 0) return { stats: sNew, melange: false };
  if (!nNew || (nNew.home + nNew.away) === 0) return { stats: sOld, melange: false, seulAncien: true };

  const num = v => { const x = Number(v); return isFinite(x) ? x : 0; };
  const mix = (aNew, cNew, aOld, cOld) => {
    const pn = cNew * POIDS_SAISON_COURANTE, po = cOld;
    if (pn + po === 0) return "0.0";
    return ((num(aNew) * pn + num(aOld) * po) / (pn + po)).toFixed(2);
  };

  const gN = sNew.goals, gO = sOld.goals;
  const out = JSON.parse(JSON.stringify(sNew));
  out.goals.for.average.home     = mix(gN.for.average.home,     nNew.home, gO.for.average.home,     nOld.home);
  out.goals.for.average.away     = mix(gN.for.average.away,     nNew.away, gO.for.average.away,     nOld.away);
  out.goals.against.average.home = mix(gN.against.average.home, nNew.home, gO.against.average.home, nOld.home);
  out.goals.against.average.away = mix(gN.against.average.away, nNew.away, gO.against.average.away, nOld.away);
  // Nombre de matchs pondere : sert au garde-fou "donnees insuffisantes"
  // cote app, qui doit voir un echantillon reel et non 1 seul match.
  out.fixtures.played.home  = nNew.home * POIDS_SAISON_COURANTE + nOld.home;
  out.fixtures.played.away  = nNew.away * POIDS_SAISON_COURANTE + nOld.away;
  out.fixtures.played.total = out.fixtures.played.home + out.fixtures.played.away;
  return { stats: out, melange: true, nNew: nNew.home + nNew.away, nOld: nOld.home + nOld.away };
}


// Repli division inferieure pour les promus. Mesure le 16/08/2026 sur 41
// promus (5 pays, 3 saisons) : en montant, ils marquent 32% de moins
// (x0.683) et encaissent 98% de plus (x1.976). Backtest sur leurs 10
// premiers matchs de D1 :
//   moyenne du championnat (avant) : Brier 0.6422
//   stats D2 brutes                : Brier 0.7520  <- PIRE que l aveuglement
//   stats D2 x facteurs mesures    : Brier 0.5894  <- retenu
// Ne JAMAIS utiliser les stats D2 sans ces facteurs.
const FACTEUR_PROMU_ATT = 0.683;
const FACTEUR_PROMU_DEF = 1.976;
const LIGUE_INFERIEURE = {
  "140": 141, // La Liga -> Segunda
  "39": 40,   // Premier League -> Championship
  "135": 136, // Serie A -> Serie B
  "78": 79,   // Bundesliga -> 2. Bundesliga
  "61": 62,   // Ligue 1 -> Ligue 2
  "94": 95    // Primeira Liga -> Liga Portugal 2
};

function corrigePromu(sD2) {
  const out = JSON.parse(JSON.stringify(sD2));
  const fix = (v, f) => {
    const x = Number(v);
    return isFinite(x) ? (x * f).toFixed(2) : v;
  };
  out.goals.for.average.home     = fix(out.goals.for.average.home,     FACTEUR_PROMU_ATT);
  out.goals.for.average.away     = fix(out.goals.for.average.away,     FACTEUR_PROMU_ATT);
  out.goals.against.average.home = fix(out.goals.against.average.home, FACTEUR_PROMU_DEF);
  out.goals.against.average.away = fix(out.goals.against.average.away, FACTEUR_PROMU_DEF);
  return out;
}

async function getTeamStatsWithFallback(env, league, season, teamId) {
  // Round 16 — repli sur la saison précédente. Avant la 1ère journée d'une
  // saison, API-Football répond valablement (200) mais avec 0 match joué :
  // ni erreur réseau, ni "équipe introuvable", juste rien à calculer.
  // Plutôt que de laisser un calcul basé sur du vide, on retombe
  // automatiquement sur la saison précédente complète (même compétition,
  // adversaires comparables) dès que la saison demandée a 0 match joué pour
  // CETTE équipe. Toujours signalé (usedFallback), jamais silencieux.
  // Modifie le 16/08/2026 : au lieu de basculer en tout-ou-rien sur la
  // saison precedente quand la courante est vide, on MELANGE les deux des
  // que la saison en cours compte peu de matchs. Avec 1 match joue,
  // l ancien code gardait ce seul match et jetait les 34 de l an dernier.
  const stats = await getTeamStatsForSeason(env, league, season, teamId);
  const played = stats?.fixtures?.played?.total ?? 0;
  const prevSeason = String(Number(season) - 1);

  // Au-dela de 12 matchs, la saison en cours se suffit a elle-meme.
  if (played >= 12) return { stats, season, usedFallback: false };

  const prevStats = await getTeamStatsForSeason(env, league, prevSeason, teamId);
  const prevPlayed = prevStats?.fixtures?.played?.total ?? 0;

  // Promu probable : rien dans cette ligue la saison passee. On tente la
  // division inferieure, corrigee par les facteurs mesures.
  let d2Corrige = null;
  if (prevPlayed === 0 && LIGUE_INFERIEURE[String(league)]) {
    try {
      const sD2 = await getTeamStatsForSeason(env, LIGUE_INFERIEURE[String(league)], prevSeason, teamId);
      if ((sD2?.fixtures?.played?.total ?? 0) > 0) d2Corrige = corrigePromu(sD2);
    } catch (err) { /* best-effort : sans D2 on retombe sur l existant */ }
  }

  if (played > 0 && prevPlayed > 0) {
    const m = melangeStats(stats, prevStats);
    return { stats: m.stats, season, usedFallback: false, melange: true,
             nNew: m.nNew, nOld: m.nOld, prevSeason };
  }
  if (played > 0 && d2Corrige) {
    const m = melangeStats(stats, d2Corrige);
    return { stats: m.stats, season, usedFallback: false, melange: true, promu: true,
             nNew: m.nNew, nOld: m.nOld, prevSeason };
  }
  if (played > 0) return { stats, season, usedFallback: false };
  if (prevPlayed > 0) return { stats: prevStats, season: prevSeason, usedFallback: true };
  if (d2Corrige) return { stats: d2Corrige, season: prevSeason, usedFallback: true, promu: true };

  // Ni la saison demandée ni la précédente n'ont de matchs pour cette
  // équipe (ex. équipe fraîchement promue, jamais vue dans cette
  // compétition) — on renvoie les stats vides de la saison demandée,
  // comme avant ce round. Limite connue et acceptée : pour cette équipe,
  // le repli ne trouve rien non plus.
  return { stats, season, usedFallback: false };
}

function sumPlayed(table) {
  return table.reduce((s, t) => s + (t?.home?.played ?? 0) + (t?.away?.played ?? 0), 0);
}

async function getStandingsWithFallback(env, league, season) {
  // Même logique de repli que getTeamStatsWithFallback, appliquée au
  // classement complet (sert à calculer lgH/lgA, la vraie moyenne du
  // championnat utilisée par le shrinkage côté client).
  const standings = await apiFootballGet(env, "/standings", { league, season });
  const table = standings?.[0]?.league?.standings?.[0] || [];
  if (sumPlayed(table) > 0) return { table, season, usedFallback: false };

  const prevSeason = String(Number(season) - 1);
  const prevStandings = await apiFootballGet(env, "/standings", { league, season: prevSeason });
  const prevTable = prevStandings?.[0]?.league?.standings?.[0] || [];
  if (sumPlayed(prevTable) > 0) return { table: prevTable, season: prevSeason, usedFallback: true };

  return { table, season, usedFallback: false };
}


// Complete l historique de la saison en cours avec la precedente quand il
// est trop court. Sans ca, la ponderation par recence (Round 15) recalculait
// a1..a4 sur les seuls matchs de la saison courante -- 1 match en aout -- et
// ecrasait le melange des deux saisons fait plus haut. Les matchs recents
// sont comptes deux fois : meme poids que melangeStats.
async function fixturesAvecMelange(env, league, season, teamId) {
  const recents = await getRecentFixtures(env, league, season, teamId);
  if (recents.length >= 12) return recents;
  try {
    const prev = await getRecentFixtures(env, league, String(Number(season) - 1), teamId);
    if (!prev.length) return recents;
    return [].concat(recents, recents, prev);
  } catch (err) {
    return recents;
  }
}

async function getGoalStats(env, league, season, homeId, awayId) {
  // Cache court (1h) : contrairement aux IDs de ligue/équipe, les stats et
  // le classement changent à chaque journée jouée — on ne veut pas d'un
  // résultat périmé, juste éviter de retaper l'API plusieurs fois pour le
  // même match dans l'heure (plusieurs utilisateurs qui analysent le même
  // match, ou l'utilisateur qui relance après un échec partiel).
  const cacheKey = "stats:" + league + ":" + season + ":" + homeId + ":" + awayId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const warnings = [];

  // Séquentiel, pas Promise.all — même raison que resolveTeam ci-dessus.
  const homeResult = await getTeamStatsWithFallback(env, league, season, homeId);
  const awayResult = await getTeamStatsWithFallback(env, league, season, awayId);
  const homeStats = homeResult.stats, awayStats = awayResult.stats;
  if (homeResult.usedFallback) {
    warnings.push("repli sur la saison " + homeResult.season + " pour l'équipe à domicile (aucun match joué en " + season + ")");
  }
  if (awayResult.usedFallback) {
    warnings.push("repli sur la saison " + awayResult.season + " pour l'équipe à l'extérieur (aucun match joué en " + season + ")");
  }
  if (homeResult.promu) {
    warnings.push("équipe à domicile promue : stats de division inférieure corrigées (attaque x0.68, défense x1.98 — facteurs mesurés sur 41 promus)");
  }
  if (awayResult.promu) {
    warnings.push("équipe à l'extérieur promue : stats de division inférieure corrigées (attaque x0.68, défense x1.98 — facteurs mesurés sur 41 promus)");
  }

  const standingsResult = await getStandingsWithFallback(env, league, season);
  if (standingsResult.usedFallback) {
    warnings.push("repli sur la saison " + standingsResult.season + " pour la moyenne du championnat (aucun match joué en " + season + ")");
  }

  // Moyennes de saison (comportement historique) — servent de repli si la
  // pondération récente ci-dessous échoue pour une raison quelconque.
  let a1 = parseFloat(homeStats?.goals?.for?.average?.home);
  let a2 = parseFloat(homeStats?.goals?.against?.average?.home);
  let a3 = parseFloat(awayStats?.goals?.for?.average?.away);
  let a4 = parseFloat(awayStats?.goals?.against?.average?.away);
  const nH = homeStats?.fixtures?.played?.home;
  const nA = awayStats?.fixtures?.played?.away;

  // Round 15 — si on arrive à récupérer l'historique match par match
  // (/fixtures), on remplace les moyennes plates ci-dessus par une moyenne
  // pondérée qui privilégie la forme récente. Utilise la saison
  // effectivement retenue ci-dessus (celle de repli si applicable), pour
  // rester cohérent avec les stats déjà récupérées. Toujours séquentiel,
  // même raison de rate-limit que les appels au-dessus.
  try {
    const homeFixtures = await fixturesAvecMelange(env, league, homeResult.season, homeId);
    const awayFixtures = await fixturesAvecMelange(env, league, awayResult.season, awayId);
    const homeAtHome = homeFixtures.filter(f => f.teams?.home?.id === homeId);
    const awayAtAway = awayFixtures.filter(f => f.teams?.away?.id === awayId);
    const dateOf = f => f.fixture?.date;
    const wa1 = weightedRecentAverage(homeAtHome, dateOf, f => f.goals?.home);
    const wa2 = weightedRecentAverage(homeAtHome, dateOf, f => f.goals?.away);
    const wa3 = weightedRecentAverage(awayAtAway, dateOf, f => f.goals?.away);
    const wa4 = weightedRecentAverage(awayAtAway, dateOf, f => f.goals?.home);
    // On ne remplace que les valeurs effectivement trouvées — sinon on garde
    // la moyenne de saison plutôt qu'un null qui viderait le champ pour rien.
    if (wa1 !== null) a1 = wa1;
    if (wa2 !== null) a2 = wa2;
    if (wa3 !== null) a3 = wa3;
    if (wa4 !== null) a4 = wa4;
  } catch (err) {
    // Best-effort : la pondération récente est une amélioration, pas une
    // dépendance dure — un échec ici (ex. /fixtures indisponible) ne doit
    // jamais faire échouer tout le calcul de stats, seulement faire
    // retomber sur la moyenne de saison classique.
  }

  const table = standingsResult.table;
  let sumHomeFor = 0, sumHomePlayed = 0, sumAwayFor = 0, sumAwayPlayed = 0;
  table.forEach(t => {
    sumHomeFor += t?.home?.goals?.for ?? 0;
    sumHomePlayed += t?.home?.played ?? 0;
    sumAwayFor += t?.away?.goals?.for ?? 0;
    sumAwayPlayed += t?.away?.played ?? 0;
  });
  const lgH = sumHomePlayed ? sumHomeFor / sumHomePlayed : null;
  const lgA = sumAwayPlayed ? sumAwayFor / sumAwayPlayed : null;

  // Correctif (audit du 30/07/2026) : on renvoie aussi la saison
  // effectivement utilisée par chaque équipe (celle du repli si le Round 16
  // s'est déclenché) — sert notamment aux blessures (Round 22), qui doivent
  // interroger la même saison que les stats déjà calculées, pas la saison
  // brute demandée à l'origine (sinon, sur un match en tout début de
  // saison — le cas typique qui déclenche justement ce repli — les
  // blessures interrogeraient une saison qui n'a pas encore commencé).
  const out = {
    a1, a2, a3, a4, nH, nA, lgH, lgA, warnings,
    homeSeasonUsed: homeResult.season,
    awaySeasonUsed: awayResult.season,
  };
  await cacheSet(env, cacheKey, out, 3600); // 1 heure
  return out;
}

/* =====================================================
   UNDERSTAT (inchangé)
   ===================================================== */
const UNDERSTAT_LEAGUES = {
  "premier league": "EPL", "epl": "EPL", "angleterre": "EPL",
  "la liga": "La_liga", "laliga": "La_liga", "espagne": "La_liga",
  "bundesliga": "Bundesliga", "allemagne": "Bundesliga",
  "serie a": "Serie_A", "italie": "Serie_A",
  "ligue 1": "Ligue_1", "france": "Ligue_1",
  "rfpl": "RFPL", "russie": "RFPL",
};
function understatSlugFor(leagueName) {
  return UNDERSTAT_LEAGUES[(leagueName || "").toLowerCase().trim()] || null;
}

async function getUnderstatTeamsForSeason(slug, season) {
  // Round 14 — Understat a migré son site vers un rendu côté client qui
  // interroge un endpoint JSON interne (/getLeagueData/{ligue}/{saison})
  // au lieu d'embarquer les données directement dans le HTML de la page.
  // L'ancienne méthode (decodeUnderstatVar sur la page HTML) échouait
  // systématiquement depuis ce changement ("structure de page inattendue").
  // On essaie d'abord le nouvel endpoint JSON (plus rapide, pas de parsing
  // fragile de JS embarqué) ; si jamais Understat change encore de côté ou
  // que cet endpoint devient indisponible, on retombe automatiquement sur
  // l'ancienne méthode HTML plutôt que d'échouer complètement d'un coup.
  try {
    return await getUnderstatTeamsViaJsonEndpoint(slug, season);
  } catch (jsonErr) {
    try {
      return await getUnderstatTeamsViaHtmlScrape(slug, season);
    } catch (htmlErr) {
      throw new Error("JSON: " + jsonErr.message + " · HTML: " + htmlErr.message);
    }
  }
}

function findUnderstatTeam(teamsData, name) {
  const teams = Object.values(teamsData);
  const n = norm(name);
  return teams.find(t => norm(t.title).includes(n) || n.includes(norm(t.title))) || null;
}

async function getUnderstatTeamWithFallback(slug, season, teamName, venueSide) {
  // Round 16 — même logique de repli que côté API-Football : si l'équipe
  // n'a aucun match de ce côté (domicile ou extérieur) pour la saison
  // demandée (généralement avant la 1ère journée), on retombe sur la
  // saison précédente complète plutôt que de renvoyer un xG vide.
  // Modifie le 16/08/2026 : meme melange que cote buts reels. Sans ca, les
  // xG restaient sur la saison en cours (1 match en aout) pendant que les
  // buts portaient deja sur deux saisons -- les deux lectures ne parlaient
  // plus du meme echantillon et l app affichait des contradictions
  // permanentes. Poids 2 : chaque match de la saison en cours est compte
  // deux fois dans l historique, ce qui revient au meme calcul de moyenne.
  const teamsData = await getUnderstatTeamsForSeason(slug, season);
  const team = findUnderstatTeam(teamsData, teamName);
  const rows = (team && team.history) ? team.history.filter(m => m.h_a === venueSide) : [];
  const prevSeason = String(Number(season) - 1);

  if (rows.length >= 12) return { team, season, usedFallback: false };

  let prevTeam = null, prevRows = [];
  try {
    const prevTeamsData = await getUnderstatTeamsForSeason(slug, prevSeason);
    prevTeam = findUnderstatTeam(prevTeamsData, teamName);
    prevRows = (prevTeam && prevTeam.history) ? prevTeam.history.filter(m => m.h_a === venueSide) : [];
  } catch (err) { /* best-effort : sans saison precedente on garde ce qu on a */ }

  if (rows.length > 0 && prevRows.length > 0) {
    const melangeXG = JSON.parse(JSON.stringify(team));
    melangeXG.history = [].concat(rows, rows, prevRows);
    return { team: melangeXG, season, usedFallback: false, melange: true,
             nNew: rows.length, nOld: prevRows.length, prevSeason };
  }
  if (rows.length > 0) return { team, season, usedFallback: false };
  if (prevRows.length > 0) return { team: prevTeam, season: prevSeason, usedFallback: true };

  // Ni cette saison ni la précédente n'ont de matchs pour ce côté (ex.
  // équipe fraîchement promue, jamais vue par Understat) — on renvoie ce
  // qu'on a (potentiellement vide/absent), comme avant ce round. Limite
  // connue et acceptée, cohérente avec le reste de l'app.
  return { team: team || prevTeam, season, usedFallback: false };
}

async function getXGViaLeague(slug, season, homeName, awayName) {
  if (!slug) throw new Error("championnat non couvert par Understat");

  const warnings = [];
  const homeResult = await getUnderstatTeamWithFallback(slug, season, homeName, "h");
  const awayResult = await getUnderstatTeamWithFallback(slug, season, awayName, "a");
  if (!homeResult.team) throw new Error("équipe domicile introuvable côté Understat: " + homeName);
  if (!awayResult.team) throw new Error("équipe extérieure introuvable côté Understat: " + awayName);
  if (homeResult.usedFallback) {
    warnings.push("repli sur la saison " + homeResult.season + " pour " + homeName + " (aucun match à domicile en " + season + " côté Understat)");
  }
  if (awayResult.usedFallback) {
    warnings.push("repli sur la saison " + awayResult.season + " pour " + awayName + " (aucun match à l'extérieur en " + season + " côté Understat)");
  }

  const side = (team, s) => team.history.filter(m => m.h_a === s);
  const hRows = side(homeResult.team, "h"), aRows = side(awayResult.team, "a");

  // Round 15 — même pondération récente que côté buts réels : les 6
  // derniers matchs de chaque équipe (à domicile pour hRows, à l'extérieur
  // pour aRows) comptent double par rapport aux matchs plus anciens de la
  // saison. `weightedRecentAverage` est définie plus haut dans ce fichier
  // (section API-Football), réutilisée ici telle quelle.
  const dateOf = m => m.date;
  return {
    b1: weightedRecentAverage(hRows, dateOf, m => parseFloat(m.xG)),
    b2: weightedRecentAverage(hRows, dateOf, m => parseFloat(m.xGA)),
    b3: weightedRecentAverage(aRows, dateOf, m => parseFloat(m.xG)),
    b4: weightedRecentAverage(aRows, dateOf, m => parseFloat(m.xGA)),
    warnings,
  };
}

async function getUnderstatTeamsViaJsonEndpoint(slug, season) {
  const url = "https://understat.com/getLeagueData/" + slug + "/" + season;
  const res = await fetchT(url, {
    headers: {
      "X-Requested-With": "XMLHttpRequest",
      "Accept": "application/json",
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    },
  });
  if (!res.ok) throw new Error("HTTP " + res.status + " (getLeagueData)");
  const body = await res.json();
  if (!body || typeof body !== "object" || !body.teams) {
    throw new Error("structure de réponse inattendue (getLeagueData)");
  }
  return body.teams;
}

async function getUnderstatTeamsViaHtmlScrape(slug, season) {
  const url = "https://understat.com/league/" + slug + "/" + season;
  const res = await fetchT(url);
  if (!res.ok) throw new Error("HTTP " + res.status);
  const html = await res.text();
  const teamsData = decodeUnderstatVar(html, "teamsData");
  if (!teamsData) throw new Error("structure de page inattendue (variable teamsData)");
  return teamsData;
}

function decodeUnderstatVar(html, varName) {
  const re = new RegExp(varName + "\\s*=\\s*JSON\\.parse\\('(.+?)'\\)");
  const m = html.match(re);
  if (!m) return null;
  const escaped = m[1];
  const bytes = [];
  let i = 0;
  while (i < escaped.length) {
    if (escaped[i] === "\\" && escaped[i + 1] === "x") {
      bytes.push(parseInt(escaped.substr(i + 2, 2), 16));
      i += 4;
    } else {
      bytes.push(escaped.charCodeAt(i));
      i += 1;
    }
  }
  return JSON.parse(new TextDecoder("utf-8").decode(new Uint8Array(bytes)));
}

/* =====================================================
   THE ODDS API (inchangé)
   ===================================================== */
async function resolveSportKey(env, leagueName) {
  // Cache long (30 jours), même logique que resolveLeague : la correspondance
  // championnat → clé "sport" de The Odds API ne change quasiment jamais,
  // pas besoin de refaire cet appel à chaque recherche.
  const cacheKey = "sportkey:" + norm(leagueName);
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const res = await fetchT("https://api.the-odds-api.com/v4/sports?apiKey=" + env.ODDS_API_KEY);
  if (!res.ok) throw new Error("HTTP " + res.status + " (liste des sports) — clé longueur=" + (env.ODDS_API_KEY || "").length);
  const list = await res.json();
  const n = norm(leagueName);
  const match = list.find(s => s.group === "Soccer" && (norm(s.title).includes(n) || n.includes(norm(s.title))));
  if (!match) throw new Error("championnat introuvable: " + leagueName);
  await cacheSet(env, cacheKey, match.key, 2592000); // 30 jours
  return match.key;
}

// Choix assumé de Tristan (15/08/2026) : restreindre The Odds API à 3
// bookmakers français précis plutôt que toute la région "eu" (~20 books).
// Bet365 était demandé en plus, mais n'existe tout simplement pas dans le
// catalogue The Odds API pour le football (vérifié dans leur doc
// officielle — seul "bet365_au", Australie/AFL-NRL, sans rapport) ; pas
// une limitation de ce projet, une vraie absence côté fournisseur.
// Conséquence attendue, pas un bug : avec seulement 3 books au lieu de
// ~20, "cote isolée" ne se déclenchera presque plus (il faut un vrai
// désaccord entre peu de sources pour l'écart% de spread() de s'affoler),
// et certains marchés moins standards (ex. total 1,5 but) peuvent
// disparaître plus souvent faute d'être proposés par ces 3 précisément.
// pinnacle ajoute le 17/08/2026 : REPERE uniquement (non jouable depuis la
// France). Extrait AVANT la collecte des cotes jouables -- il ne doit
// jamais devenir "meilleure cote". Le backtest du 15/08 a montre qu acheter
// les ecarts vs Pinnacle PERD (-0.97% a +2, -12.95% a +10) : c est un
// repere de contexte (no-vig = probabilite de reference), pas un signal.
const PREFERRED_BOOKMAKERS = "winamax_fr,betclic_fr,pmu_fr,bet365,unibet_fr,bwin,pinnacle";
const PINNACLE_REPERE = /^pinnacle$/i;

// Voir GET /api/journee ci-dessus.
const JOURNEE_MIENS = /^(betclic|winamax|pmu)\s*\(?fr\)?$/i;
async function handleJournee(env, sport) {
  const url = "https://api.the-odds-api.com/v4/sports/" + sport + "/odds"
    + "?apiKey=" + env.ODDS_API_KEY
    + "&regions=eu&markets=h2h,totals&oddsFormat=decimal";
  const r = await fetchT(url);
  if (!r.ok) {
    const body = await r.text().catch(() => "");
    throw new Error("Odds API HTTP " + r.status + " -- " + body.slice(0, 150));
  }
  const evts = await r.json();
  const restant = r.headers.get("x-requests-remaining");
  const matchs = evts.map(e => {
    const mien = {}, pinn = {};
    (e.bookmakers || []).forEach(bk => {
      const cible = JOURNEE_MIENS.test(bk.title) ? mien
                  : /^pinnacle$/i.test(bk.title) ? pinn : null;
      if (!cible) return;
      (bk.markets || []).forEach(mk => (mk.outcomes || []).forEach(o => {
        const k = mk.key + "|" + o.name + (o.point !== undefined ? " " + o.point : "");
        if (!cible[k] || o.price > cible[k].price) cible[k] = { price: o.price, book: bk.title };
      }));
    });
    return { home: e.home_team, away: e.away_team, commence: e.commence_time, mien, pinn };
  }).sort((a, b) => new Date(a.commence) - new Date(b.commence));
  return { sport, restant, count: matchs.length, matchs };
}

async function fetchOddsEvents(env, sportKey, markets) {
  const url = "https://api.the-odds-api.com/v4/sports/" + sportKey + "/odds"
    + "?apiKey=" + env.ODDS_API_KEY + "&bookmakers=" + PREFERRED_BOOKMAKERS + "&markets=" + markets + "&oddsFormat=decimal";
  const res = await fetchT(url);
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error("HTTP " + res.status + " sportKey=" + sportKey + " markets=" + markets
      + " clé longueur=" + (env.ODDS_API_KEY || "").length + " — " + body.slice(0, 200));
  }
  return res.json();
}

// Coût : 3 marchés x 1 région = 3 crédits par appel côté The Odds API.
// Tier gratuit (500 crédits/mois) = ~166 matchs/mois. Passer en payant
// (~30$/mois, 20 000 requêtes) si usage fréquent — voir README §2.
// Comparaison de noms d'équipe robuste : égalité, inclusion dans un sens ou
// l'autre, puis en dernier recours un préfixe commun de 5 caractères (utile
// pour des variantes proches comme "Botafogo" vs "Botafogo RJ").
function teamNameMatches(a, b) {
  const na = norm(a), nb = norm(b);
  if (!na || !nb) return false;
  if (na === nb || na.includes(nb) || nb.includes(na)) return true;
  const minLen = Math.min(na.length, nb.length);
  return minLen >= 5 && na.slice(0, 5) === nb.slice(0, 5);
}

// Ajouté le 15/08/2026 — secours OddsPapi, UNIQUEMENT quand The Odds API +
// les 3 books préférés (Winamax/Unibet/Betclic) ne renvoient AUCUNE cote de
// totaux (cas fréquent constaté ce soir : flux pas encore synchronisé pour
// ces lignes secondaires). Jamais appelé sur un match où les totaux
// existent déjà — décision assumée de Tristan pour préserver le quota
// gratuit (250 requêtes/mois OddsPapi, ~2/appel ici). Best-effort strict :
// toute erreur ici (quota dépassé, clé absente, match introuvable) est
// avalée silencieusement — l'app doit continuer à fonctionner exactement
// comme avant si ce secours échoue, jamais de plantage à cause de lui.
// Ajouté le 15/08/2026 -- les books "exotiques" remontés par le secours
// OddsPapi (marchés de prédiction comme kalshi/polymarket -- ce ne sont
// pas des bookmakers classiques -- ou books inaccessibles/non pertinents
// depuis la France comme fonbet/4casters) déformaient le calcul de value
// avec des prix qu'on ne peut jamais réellement obtenir en pratique.
// Liste de départ basée sur la doc publique OddsPapi -- à ajuster si les
// slugs réels observés en usage diffèrent (voir avertissement "book(s)
// OddsPapi ignoré(s)" affiché quand un book est écarté par ce filtre).
const ODDSPAPI_TRUSTED_BOOKS = [
  "pinnacle", "bet365", "unibet", "bwin", "betclic",
  "williamhill", "betfair", "marathonbet", "1xbet", "betsson",
];

const COMPETS_PARASITES = /\b(srl|simulated|women|femin|u1[6-9]|u2[0-3]|youth|reserve|esport|cyber)\b/i;
function oddsPapiFixturePropre(matches) {
  const propres = matches.filter(f => {
    const c = [f.tournamentName, f.categoryName, f.tournamentSlug, f.categorySlug,
               f.participant1Name, f.participant2Name].join(' ');
    if (COMPETS_PARASITES.test(c)) return false;
    if (f.statusName === 'Live' || f.statusName === 'Finished') return false;
    if (f.hasOdds === false) return false;
    return true;
  });
  if (!propres.length) {
    const vus = matches.slice(0, 4).map(f =>
      f.participant1Name + ' vs ' + f.participant2Name
      + ' [' + f.tournamentName + ', ' + f.statusName + ']').join(' | ');
    throw new Error('OddsPapi : aucun match reel a venir parmi '
      + matches.length + ' correspondance(s) -- ' + vus);
  }
  propres.sort((a, b) => new Date(a.startTime || 0) - new Date(b.startTime || 0));
  return propres[0];
}

async function fetchOddsPapiTotalsFallback(env, homeName, awayName) {
  if (!env.ODDSPAPI_API_KEY) throw new Error("ODDSPAPI_API_KEY absente de l'environnement serveur");
  const base = "https://api.oddspapi.io/v4";
  const today = new Date().toISOString().slice(0, 10);
  const in9days = new Date(Date.now() + 9 * 86400000).toISOString().slice(0, 10);
  const fixturesRes = await fetchT(`${base}/fixtures?apiKey=${env.ODDSPAPI_API_KEY}&sportId=10&from=${today}&to=${in9days}`);
  if (!fixturesRes.ok) {
    const body = await fixturesRes.text().catch(() => "");
    throw new Error("OddsPapi fixtures HTTP " + fixturesRes.status + " — " + body.slice(0, 150));
  }
  const fixtures = await fixturesRes.json();
  const matches = fixtures.filter(f => teamNameMatches(f.participant1Name, homeName) && teamNameMatches(f.participant2Name, awayName));
  if (!matches.length) throw new Error("OddsPapi : match \"" + homeName + "\" vs \"" + awayName + "\" introuvable parmi " + fixtures.length + " matchs (9 prochains jours)");
  // Round 39-bis : un même match peut apparaître en double avec un statut
  // "Live" erroné même des heures avant le coup d'envoi (bug constaté ce
  // soir sur Alaves-Getafe) — on préfère systématiquement un doublon non
  // marqué "Live" quand il en existe un.
  // Corrige le 15/08/2026 : un doublon "Finished" (match deja termine, dans
  // une autre saison ou compet.) passait ce filtre puisqu'il n'etait pas
  // "Live" -- et s'il apparait en premier dans la liste (constate sur
  // Alaves-Getafe), c'est LUI qui etait choisi au lieu du vrai match a
  // venir, avec des cotes forcement vides ou perimees. On exclut desormais
  // aussi "Finished".
  const fixture = oddsPapiFixturePropre(matches);

  const oddsRes = await fetchT(`${base}/odds?apiKey=${env.ODDSPAPI_API_KEY}&fixtureId=${fixture.fixtureId}`);
  if (!oddsRes.ok) {
    const body = await oddsRes.text().catch(() => "");
    throw new Error("OddsPapi odds HTTP " + oddsRes.status + " (fixture " + fixture.statusName + ") — " + body.slice(0, 150));
  }
  const odds = await oddsRes.json();
  // Ajoute le 15/08/2026 : OddsPapi peut repondre HTTP 200 avec un corps
  // {"error": {...}} (ex. rate limit) au lieu d'un vrai HTTP d'erreur.
  // L'ancien code ne verifiait jamais ce champ et lisait silencieusement
  // "bookmakerOdds: {}" -- indiscernable d'un vrai marche absent. On leve
  // maintenant une vraie erreur explicite dans ce cas.
  if (odds.error) {
    throw new Error("OddsPapi erreur: " + (odds.error.message || JSON.stringify(odds.error)));
  }
  const bookmakerOdds = odds.bookmakerOdds || {};
  const out = { oO25: [], oU25: [], oO15: [], oU15: [] };
  // Corrige le 15/08/2026 -- 1012/1013 correspondait en realite a la ligne
  // 3,5 buts chez OddsPapi (verifie via GET /v4/markets en direct), pas a
  // la ligne 1,5 comme suppose depuis le pattern de 2,5 (1010/1011). Les
  // vrais IDs pour Over/Under 1.5 buts sont 108 (Over) / 109 (Under) --
  // une numerotation totalement differente, propre a cette ligne chez ce
  // fournisseur, pas devinable depuis le pattern des autres lignes.
  const marketMap = { "1010": "oO25", "1011": "oU25", "108": "oO15", "109": "oU15" };
  // Corrige le 15/08/2026 : OddsPapi imbrique Over ET Under sous le MEME
  // marche top-niveau (ex. le marche "1012" contient les deux outcomes
  // "1012" (Over) et "1013" (Under)). L'ancienne version cherchait
  // markets[marketId] pour chaque cle du marketMap independamment -- ca
  // fusionnait Over et Under dans le meme panier (doublait les prix, d'ou
  // des compteurs "X books" absurdes vus en prod, ex. 326) et laissait
  // Under quasiment toujours vide (son ID n'existe jamais comme cle
  // top-niveau de "markets", seulement imbrique dans les outcomes du
  // marche Over correspondant). On boucle desormais sur TOUS les marches
  // reellement presents, et c'est la cle de l'OUTCOME (pas celle du
  // marche parent) qui determine le panier de destination.
  Object.entries(bookmakerOdds).forEach(([bookSlug, bookData]) => {
    if (!ODDSPAPI_TRUSTED_BOOKS.includes(bookSlug)) return;
    const markets = bookData?.markets || {};
    Object.values(markets).forEach(market => {
      if (!market) return;
      Object.entries(market.outcomes || {}).forEach(([outcomeId, outcome]) => {
        const key = marketMap[outcomeId];
        if (!key) return;
        Object.values(outcome.players || {}).forEach(player => {
          if (typeof player.price === "number") out[key].push({ price: player.price, book: bookSlug + " (OddsPapi)" });
        });
      });
    });
  });
  const hasAny = out.oO25.length || out.oU25.length || out.oO15.length || out.oU15.length;
  return hasAny ? out : null;
}

async function fetchOddsPapiBttsFallback(env, homeName, awayName) {
  if (!env.ODDSPAPI_API_KEY) throw new Error("ODDSPAPI_API_KEY absente de l'environnement serveur");
  const base = "https://api.oddspapi.io/v4";
  const today = new Date().toISOString().slice(0, 10);
  const in9days = new Date(Date.now() + 9 * 86400000).toISOString().slice(0, 10);
  const fixturesRes = await fetchT(`${base}/fixtures?apiKey=${env.ODDSPAPI_API_KEY}&sportId=10&from=${today}&to=${in9days}`);
  if (!fixturesRes.ok) {
    const body = await fixturesRes.text().catch(() => "");
    throw new Error("OddsPapi fixtures HTTP " + fixturesRes.status + " -- " + body.slice(0, 150));
  }
  const fixtures = await fixturesRes.json();
  const matches = fixtures.filter(f => teamNameMatches(f.participant1Name, homeName) && teamNameMatches(f.participant2Name, awayName));
  if (!matches.length) throw new Error("OddsPapi : match \"" + homeName + "\" vs \"" + awayName + "\" introuvable parmi " + fixtures.length + " matchs (9 prochains jours)");
  // Même filtre Live/Finished que fetchOddsPapiTotalsFallback (voir
  // Round 39-bis / correctif du 15/08/2026 ci-dessus pour le raisonnement).
  const fixture = oddsPapiFixturePropre(matches);

  const oddsRes = await fetchT(`${base}/odds?apiKey=${env.ODDSPAPI_API_KEY}&fixtureId=${fixture.fixtureId}`);
  if (!oddsRes.ok) {
    const body = await oddsRes.text().catch(() => "");
    throw new Error("OddsPapi odds HTTP " + oddsRes.status + " (fixture " + fixture.statusName + ") -- " + body.slice(0, 150));
  }
  const odds = await oddsRes.json();
  if (odds.error) {
    throw new Error("OddsPapi erreur: " + (odds.error.message || JSON.stringify(odds.error)));
  }
  const bookmakerOdds = odds.bookmakerOdds || {};
  const out = { oBTTSyes: [], oBTTSno: [] };
  // Marché "Both Teams To Score" = marketId 104 chez OddsPapi (doc
  // officielle GET /v4/markets) -- outcomeId 104 = "Yes", 105 = "No".
  // Même logique d'indexation par outcomeId (pas par marché parent) que
  // pour Over/Under -- voir le correctif du 15/08/2026 ci-dessus.
  const marketMap = { "104": "oBTTSyes", "105": "oBTTSno" };
  Object.entries(bookmakerOdds).forEach(([bookSlug, bookData]) => {
    if (!ODDSPAPI_TRUSTED_BOOKS.includes(bookSlug)) return;
    const markets = bookData?.markets || {};
    Object.values(markets).forEach(market => {
      if (!market) return;
      Object.entries(market.outcomes || {}).forEach(([outcomeId, outcome]) => {
        const key = marketMap[outcomeId];
        if (!key) return;
        Object.values(outcome.players || {}).forEach(player => {
          if (typeof player.price === "number") out[key].push({ price: player.price, book: bookSlug + " (OddsPapi)" });
        });
      });
    });
  });
  const hasAny = out.oBTTSyes.length || out.oBTTSno.length;
  return hasAny ? out : null;
}

async function getOdds(env, sportKey, homeName, awayName) {
  let events;
  let totalsWarning = null;
  try {
    // ATTENTION : "btts" est un marché additionnel chez The Odds API, non
    // disponible sur ce point d'accès (/sports/{sport}/odds) — l'inclure
    // ici fait échouer TOUTE la requête avec "Markets not supported by
    // this endpoint: btts", ce qui faisait perdre "totals" au passage
    // (retombée sur h2h seul). BTTS nécessiterait un endpoint différent,
    // par match, potentiellement réservé à une offre payante supérieure —
    // pas encore intégré. On ne demande donc que les deux marchés valides
    // ensemble sur cet endpoint.
    events = await fetchOddsEvents(env, sportKey, "h2h,totals");
  } catch (err) {
    // Corrigé le 15/08/2026 : cet échec était avalé en silence — on
    // retombait sur le 1N2 seul sans jamais dire pourquoi "totals" avait
    // échoué (plan trop restreint, combinaison bookmakers+totals refusée,
    // etc.). Repéré en conditions réelles : avec seulement 3 bookmakers
    // précis (Winamax/Unibet/Betclic), plus aucun marché +/-2,5 ou +/-1,5
    // n'apparaissait jamais, sans le moindre avertissement, alors que ces
    // lignes existent bien chez ces books en vrai. On garde maintenant le
    // vrai message d'erreur pour le remonter à l'utilisateur.
    totalsWarning = "totals indisponibles (" + err.message + ") — repli sur 1N2 seul";
    events = await fetchOddsEvents(env, sportKey, "h2h");
  }


  // ATTENTION : il faut que domicile ET extérieur correspondent tous les
  // deux (pas l'un OU l'autre) — sinon, sur une journée avec plusieurs
  // matchs, on peut silencieusement récupérer les cotes d'un autre match
  // que celui demandé, avec une équipe à domicile complètement différente.
  const match = events.find(e => teamNameMatches(e.home_team, homeName) && teamNameMatches(e.away_team, awayName));
  if (!match) throw new Error("match introuvable côté The Odds API");

  const collect = { o1: [], oX: [], o2: [], oBTTSyes: [], oBTTSno: [], oO25: [], oU25: [], oO15: [], oU15: [] };
  // Diagnostic ajouté le 15/08/2026 : trace exactement quels marchés
  // chaque bookmaker a réellement renvoyé, pour trancher entre "vraie
  // absence de totals dans le flux The Odds API à cet instant" et "bug de
  // parsing" — question restée ouverte malgré le correctif précédent
  // (aucune erreur levée, mais aucune cote totals extraite non plus).
  const marketsSeenPerBook = {};
  // Extraction Pinnacle (repere) -- no-vig par marche : implicites divises
  // par leur somme, marge retiree. C est la meilleure estimation publique
  // de la vraie probabilite.
  const pinnacle = { p1: null, pX: null, p2: null, pO25: null, pU25: null };
  const pinBk = match.bookmakers.find(bk => PINNACLE_REPERE.test(bk.title || ""));
  if (pinBk) {
    (pinBk.markets || []).forEach(mk => {
      if (mk.key === "h2h" && mk.outcomes && mk.outcomes.length >= 3) {
        let iH = null, iD = null, iA = null;
        mk.outcomes.forEach(o => {
          const imp = 1 / o.price;
          if (o.name === match.home_team) iH = imp;
          else if (o.name === match.away_team) iA = imp;
          else iD = imp;
        });
        if (iH && iD && iA) {
          const tot = iH + iD + iA;
          pinnacle.p1 = iH / tot; pinnacle.pX = iD / tot; pinnacle.p2 = iA / tot;
        }
      }
      if (mk.key === "totals" && mk.outcomes) {
        // Pinnacle publie souvent une ligne asiatique (2.25, 2.75) plutot
        // que 2.5. On ne compare QUE la ligne 2.5 -- comparer des lignes
        // differentes serait comparer des paris differents. Quand 2.5 est
        // absente, on note la ligne publiee pour l afficher cote app.
        const points = [...new Set(mk.outcomes.map(o => o.point))];
        if (!points.includes(2.5)) pinnacle.ligneTotaux = points[0];
        let iO = null, iU = null;
        mk.outcomes.forEach(o => {
          if (o.point !== 2.5) return;
          if (/over/i.test(o.name)) iO = 1 / o.price;
          if (/under/i.test(o.name)) iU = 1 / o.price;
        });
        if (iO && iU) {
          const tot = iO + iU;
          pinnacle.pO25 = iO / tot; pinnacle.pU25 = iU / tot;
        }
      }
    });
  }

  match.bookmakers.forEach(bk => {
    if (PINNACLE_REPERE.test(bk.title || "")) return; // repere, jamais cote jouable
    marketsSeenPerBook[bk.title] = bk.markets.map(mk => mk.key).join("+") || "(aucun marché)";
    bk.markets.forEach(mk => {
      if (mk.key === "h2h") mk.outcomes.forEach(o => {
        if (o.name === match.home_team) collect.o1.push({ price: o.price, book: bk.title });
        else if (o.name === match.away_team) collect.o2.push({ price: o.price, book: bk.title });
        else collect.oX.push({ price: o.price, book: bk.title });
      });
      if (mk.key === "btts") mk.outcomes.forEach(o => {
        if (/yes/i.test(o.name)) collect.oBTTSyes.push({ price: o.price, book: bk.title });
        if (/no/i.test(o.name)) collect.oBTTSno.push({ price: o.price, book: bk.title });
      });
      if (mk.key === "totals") mk.outcomes.forEach(o => {
        if (o.point === 2.5 && /over/i.test(o.name)) collect.oO25.push({ price: o.price, book: bk.title });
        if (o.point === 2.5 && /under/i.test(o.name)) collect.oU25.push({ price: o.price, book: bk.title });
        if (o.point === 1.5 && /over/i.test(o.name)) collect.oO15.push({ price: o.price, book: bk.title });
        if (o.point === 1.5 && /under/i.test(o.name)) collect.oU15.push({ price: o.price, book: bk.title });
      });
    });
  });
  const noTotalsAtAll = !collect.oO25.length && !collect.oU25.length && !collect.oO15.length && !collect.oU15.length;
  if (noTotalsAtAll) {
    const originalIssue = totalsWarning; // conserve la raison d'origine si "h2h,totals" avait déjà échoué
    // Secours OddsPapi — voir fetchOddsPapiTotalsFallback ci-dessus pour le
    // raisonnement complet. Jamais fatal : si ça échoue pour n'importe
    // quelle raison, on retombe simplement sur le comportement d'avant
    // (avertissement informatif, pas de totaux).
    let fallback = null;
    let fallbackErr = null;
    try { fallback = await fetchOddsPapiTotalsFallback(env, homeName, awayName); } catch (e) { fallbackErr = e.message; }
    if (fallback) {
      collect.oO25 = fallback.oO25; collect.oU25 = fallback.oU25;
      collect.oO15 = fallback.oO15; collect.oU15 = fallback.oU15;
      totalsWarning = "totals absents chez Winamax/Unibet/Betclic — complétés via OddsPapi (secours, " +
        (fallback.oO25.length + fallback.oU25.length + fallback.oO15.length + fallback.oU15.length) + " cotes trouvées)";
    } else {
      const detail = Object.keys(marketsSeenPerBook).length
        ? Object.entries(marketsSeenPerBook).map(([book, mks]) => book + " : " + mks).join(" · ")
        : "aucun bookmaker demandé n'a répondu pour ce match";
      totalsWarning = (originalIssue ? originalIssue + " · " : "") +
        "aucune cote 1,5/2,5 reçue (secours OddsPapi : " + (fallbackErr ? "erreur — " + fallbackErr : "exécuté sans erreur mais sans donnée") + ") — marchés reçus par book (Odds API) : " + detail;
    }
  }

  const noBttsAtAll = !collect.oBTTSyes.length && !collect.oBTTSno.length;
if (noBttsAtAll) {
  // Secours OddsPapi pour BTTS -- même principe que noTotalsAtAll
  // ci-dessus. Jamais fatal : si ça échoue, "cote --" reste affiché
  // comme avant, sans casser le reste du lookup.
  let bttsFallback = null;
  let bttsFallbackErr = null;
  try { bttsFallback = await fetchOddsPapiBttsFallback(env, homeName, awayName); } catch (e) { bttsFallbackErr = e.message; }
  if (bttsFallback) {
    collect.oBTTSyes = bttsFallback.oBTTSyes;
    collect.oBTTSno = bttsFallback.oBTTSno;
    totalsWarning = (totalsWarning ? totalsWarning + " · " : "") +
      "BTTS absent chez Winamax/Unibet/Betclic -- complété via OddsPapi (secours, " +
      (bttsFallback.oBTTSyes.length + bttsFallback.oBTTSno.length) + " cotes trouvées)";
  } else if (bttsFallbackErr) {
    totalsWarning = (totalsWarning ? totalsWarning + " · " : "") +
      "BTTS : secours OddsPapi en erreur (" + bttsFallbackErr + ")";
  }
}

// On retient la MEILLEURE cote disponible (celle qui te paierait le plus),
  // pas la moyenne : un parieur value ne mise jamais "à la moyenne", il
  // prend toujours la meilleure cote qu'il peut réellement obtenir. La
  // moyenne sous-estimait systématiquement la value réellement capturable.
  const out = {};
  const bestBook = {};
  const spread = {};
  // Priorite stricte a Betclic (seul book ou l'utilisateur joue reellement) :
  // si Betclic a un prix sur ce marche, on l'utilise toujours, meme si un
  // autre book affiche mieux -- un signal "value" n'a de sens que sur un
  // prix reellement accessible. On ne se rabat sur le meilleur prix des
  // autres books que si Betclic n'a rien sur ce marche precis, et dans ce
  // cas on le signale dans les avertissements plutot que de le faire passer
  // silencieusement pour une cote Betclic.
  const marketLabels = {
    o1: "1", oX: "N", o2: "2",
    oBTTSyes: "BTTS oui", oBTTSno: "BTTS non",
    oO25: "+2,5", oU25: "-2,5", oO15: "+1,5", oU15: "-1,5",
  };
  const offBetclicMarkets = [];
  const outlierBooks = {};
Object.keys(collect).forEach(k => {
    let arr = collect[k];
    if (!arr.length) { out[k] = null; bestBook[k] = null; spread[k] = null; return; }
    // Ajoute le 15/08/2026 -- detection de cotes aberrantes : un seul book
  // (meme normalement fiable par ailleurs) peut ponctuellement pousser un
  // prix perime ou mal calibre sur une ligne peu liquide (ex. +1,5 but).
  // Comme la selection prend toujours le prix maximum, un seul prix
  // aberrant devenait systematiquement "la" cote affichee. On calcule la
  // mediane des prix disponibles et on ecarte tout prix qui s'en eloigne
  // de plus de 3x, dans un sens ou l'autre, AVANT la selection Betclic/
  // meilleure cote. Jamais silencieux : les prix ecartes sont listes dans
  // les avertissements (voir plus bas). Si filtrer viderait le tableau ou
  // s'il y a trop peu de points pour qu'une mediane ait un sens (<3), on
  // garde tout sans filtrer.
  if (arr.length >= 3) {
    const sortedPrices = arr.map(p => p.price).slice().sort((a, b) => a - b);
    const mid = Math.floor(sortedPrices.length / 2);
    const median = sortedPrices.length % 2
      ? sortedPrices[mid]
      : (sortedPrices[mid - 1] + sortedPrices[mid]) / 2;
    const OUTLIER_RATIO = 3;
    const kept = arr.filter(p => p.price <= median * OUTLIER_RATIO && p.price >= median / OUTLIER_RATIO);
    const excluded = arr.filter(p => !kept.includes(p));
    if (kept.length && excluded.length) {
      outlierBooks[k] = excluded.map(p => p.book + " (" + p.price + ")");
      arr = kept;
    }
  }
  // Books reellement joues : Betclic FR et Winamax FR. Le test est ancre
    // pour ne pas confondre avec betclic.pt / winamax.es, non jouables ici.
    const MY_BOOKS = /^(betclic|winamax|pmu)(\s*\(?fr\)?)?$/i;
    const mine = arr.filter(p => MY_BOOKS.test(String(p.book || '').trim()));
    let best, min = arr[0].price, max = arr[0].price;
    if (mine.length) {
      // Meilleure cote parmi MES books uniquement.
      best = mine[0];
      mine.forEach(p => { if (p.price > best.price) best = p; });
    } else {
      // Aucun de mes books sur ce marche : on prend la meilleure cote
      // disponible a titre indicatif, et on le signale explicitement.
      best = arr[0];
      arr.forEach(p => { if (p.price > best.price) best = p; });
      offBetclicMarkets.push(k);
    }
    arr.forEach(p => {
      if (p.price < min) min = p.price;
      if (p.price > max) max = p.price;
    });
    out[k] = best.price;
    bestBook[k] = best.book;
    spread[k] = { spread: max - min, count: arr.length };
  });
  out.spread = spread;
  out.bestBook = bestBook;
  out.pinnacle = pinnacle; // repere no-vig, extrait avant la collecte
  if (offBetclicMarkets.length) {
    const labels = offBetclicMarkets.map(k => marketLabels[k] || k).join(", ");
    const betclicMsg = "cote(s) hors Betclic/Winamax (marche indisponible chez tes books) : "
      + labels + " -- verifie le book avant de jouer";
    // Reutilise la variable totalsWarning deja existante plus haut dans la
    // fonction (deja branchee sur out.warning -> warnings affiches a
    // l'utilisateur) au lieu d'un nouveau champ qui ne serait jamais lu.
    totalsWarning = (totalsWarning ? totalsWarning + " · " : "") + betclicMsg;
  }
  if (Object.keys(outlierBooks).length) {
    const outlierLabels = Object.entries(outlierBooks)
      .map(([k, books]) => (marketLabels[k] || k) + " : " + books.join(", "))
      .join(" · ");
    totalsWarning = (totalsWarning ? totalsWarning + " · " : "") +
      "cote(s) aberrante(s) ecartee(s) (plus de 3x la mediane du marche) : " + outlierLabels;
  }
  out.warning = totalsWarning;
  return out;
}

// Fallback en cas de panne ponctuelle de The Odds API : on garde en cache
// la dernière cote connue par match pendant 6h. Si la source est en panne
// (pas juste un rate limit ponctuel — un vrai incident fournisseur), on sert
// cette dernière valeur plutôt que de faire échouer tout le lookup, avec un
// avertissement clair qui précise l'âge de la donnée.
const ODDS_FALLBACK_TTL = 6 * 3600;
async function getOddsCached(env, sportKey, homeName, awayName) {
  const fallbackKey = "oddsfallback:" + sportKey + ":" + norm(homeName) + ":" + norm(awayName);
  try {
    const out = await getOdds(env, sportKey, homeName, awayName);
    await cacheSet(env, fallbackKey, { out, savedAt: Date.now() }, ODDS_FALLBACK_TTL);
    // Corrigé le 15/08/2026 : cette ligne écrasait systématiquement le
    // warning éventuel de getOdds() (ex. "totals indisponibles") avec
    // null codé en dur — un vrai avertissement produit plus haut était
    // silencieusement perdu ici, à l'étape suivante.
    return { odds: out, warning: out.warning || null };
  } catch (err) {
    const fallback = await cacheGet(env, fallbackKey);
    if (fallback) {
      const ageMin = Math.max(1, Math.round((Date.now() - fallback.savedAt) / 60000));
      return {
        odds: fallback.out,
        warning: "cotes (The Odds API): panne en direct (" + err.message + ") — cotes en cache utilisées, datant d'environ " + ageMin + " min",
      };
    }
    throw err;
  }
}

/* =====================================================
   FOOTBALL-DATA.CO.UK — vraie moyenne de buts du championnat
   Site NON bloqué (testé). Fichiers CSV gratuits, deux formats :
   - "Grands" championnats : mmz4281/{saison}/{code}.csv (ex: F1 = Ligue 1)
     un fichier par saison, colonnes FTHG/FTAG (buts domicile/extérieur)
   - "Extra" championnats : new/{code}.csv (ex: SWE = Suède)
     un seul fichier, toutes saisons, colonnes Season/HG/AG à filtrer
   Le code pays MEX et SWE ont été vérifiés en conditions réelles ;
   les autres sont des codes probables non testés — si l'un échoue,
   c'est le premier endroit à corriger (vérifier sur football-data.co.uk).
   ===================================================== */
const MAIN_LEAGUES_FD = {
  england: "E0", angleterre: "E0",
  scotland: "SC0", ecosse: "SC0",
  germany: "D1", allemagne: "D1",
  italy: "I1", italie: "I1",
  spain: "SP1", espagne: "SP1",
  france: "F1",
  netherlands: "N1", "pays-bas": "N1",
  belgium: "B1", belgique: "B1",
  portugal: "P1",
  turkey: "T1", turquie: "T1",
  greece: "G1", grece: "G1",
};
// Bug trouvé en audit le 14/08/2026 : la moyenne du championnat était
// résolue UNIQUEMENT par pays (MAIN_LEAGUES_FD ci-dessus), jamais par le
// nom du championnat lui-même. Pour un pays qui a plusieurs divisions
// suivies par football-data.co.uk, n'importe quelle division demandée
// renvoyait donc silencieusement le code de l'ÉLITE — ex. "2. Bundesliga"
// résolu comme "D1" (la vraie Bundesliga), pas "D2". Repéré ce soir sous
// forme d'erreur HTTP (fichier saison pas encore publié pour ce code), mais
// le vrai danger est pire : sur une saison où le fichier D1 existe déjà,
// ça aurait réussi silencieusement avec les MAUVAISES moyennes, sans le
// moindre avertissement — exactement le genre de faille que ce projet
// évite partout ailleurs (cf. buildImportCode). Cette table résout
// maintenant par NOM DE CHAMPIONNAT en priorité, pour les pays où
// plusieurs divisions sont suivies.
const TIERED_COUNTRIES_FD = new Set(["england", "angleterre", "germany", "allemagne", "spain", "espagne", "italy", "italie", "france"]);
const LEAGUE_NAME_TO_FD = {
  "premier league": "E0",
  championship: "E1", "efl championship": "E1",
  bundesliga: "D1", "1 bundesliga": "D1", "1. bundesliga": "D1",
  "2 bundesliga": "D2", "2. bundesliga": "D2", "zweite bundesliga": "D2",
  "la liga": "SP1", laliga: "SP1", "primera division": "SP1",
  "segunda division": "SP2", "la liga 2": "SP2", laliga2: "SP2",
  "serie a": "I1",
  "serie b": "I2",
  "ligue 1": "F1",
  "ligue 2": "F2",
};
const EXTRA_LEAGUES_FD = {
  argentina: "ARG", argentine: "ARG",
  austria: "AUT", autriche: "AUT",
  brazil: "BRA", bresil: "BRA",
  china: "CHN", chine: "CHN",
  denmark: "DNK", danemark: "DNK",
  finland: "FIN", finlande: "FIN",
  ireland: "IRL", irlande: "IRL",
  japan: "JPN", japon: "JPN",
  mexico: "MEX", mexique: "MEX", // vérifié
  norway: "NOR", norvege: "NOR",
  poland: "POL", pologne: "POL",
  romania: "ROU", roumanie: "ROU",
  russia: "RUS", russie: "RUS",
  sweden: "SWE", suede: "SWE", // vérifié
  switzerland: "CHE", suisse: "CHE",
  usa: "USA", "etats-unis": "USA", unitedstates: "USA",
};

// Round 19 — vérifie si un nom de pays (tel que renvoyé par API-Football,
// ex. "England", "Spain") correspond à un code connu de football-data.co.uk,
// pour savoir si l'auto-détection peut s'appliquer (sinon on ne fait rien de
// spécial : le calcul retombe sur l'estimation via /standings, comme avant).
function isKnownFDCountry(countryName) {
  const key = norm(countryName);
  return Object.keys(MAIN_LEAGUES_FD).some(k => norm(k) === key)
    || Object.keys(EXTRA_LEAGUES_FD).some(k => norm(k) === key);
}

// Round 19 — résout le pays d'un championnat à partir de son ID
// (contrairement à resolveLeague, qui cherche par nom libre). Utilisé par
// handleMatch (Scan), où l'ID est déjà connu mais pas le pays. Cache long
// (30 jours, même logique que resolveLeague) : le pays d'une ligue ne change
// jamais.
async function getLeagueCountry(env, leagueId) {
  const cacheKey = "leaguecountry:" + leagueId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  const res = await apiFootballGet(env, "/leagues", { id: leagueId });
  const country = res?.[0]?.country?.name || null;
  if (country) await cacheSet(env, cacheKey, country, 2592000); // 30 jours
  return country;
}

// Round 22 — forme et composition d'équipe (blessures/suspensions).
// D'après la documentation officielle API-Football, chaque championnat/
// saison a un indicateur coverage.injuries dans /leagues (visible par
// saison, dans seasons[].coverage.injuries) : s'il est faux, l'API ne
// collecte tout simplement pas cette donnée pour ce championnat — pas
// une erreur, juste une absence de couverture à gérer silencieusement,
// exactement comme BTTS pour les cotes. On vérifie donc toujours ce
// drapeau avant d'appeler /injuries, pour ne jamais présenter un
// "0 blessure" comme une information fiable alors que la source ne
// couvre simplement pas cette ligue.
async function getLeagueInjuryCoverage(env, leagueId, season) {
  const cacheKey = "injurycoverage:" + leagueId + ":" + season;
  const cached = await cacheGet(env, cacheKey);
  if (cached !== null) return cached;
  const res = await apiFootballGet(env, "/leagues", { id: leagueId });
  const seasons = res?.[0]?.seasons || [];
  const seasonEntry = seasons.find(s => String(s.year) === String(season));
  const covered = !!(seasonEntry && seasonEntry.coverage && seasonEntry.coverage.injuries);
  await cacheSet(env, cacheKey, covered, 2592000); // 30 jours — la couverture d'une ligue ne change pas d'une recherche à l'autre
  return covered;
}

// ATTENTION : la forme exacte de la réponse /injuries n'a pas pu être
// vérifiée contre un vrai appel (accès réseau indisponible depuis
// l'environnement où ce code a été écrit) — seule la description textuelle
// de la documentation officielle a pu être consultée ("chaque entrée donne
// le nom du joueur, son équipe, le contexte du match, et deux champs clés :
// type (Injury ou Suspension) et reason (ex. 'Knee Injury')"), pas un
// exemple JSON littéral. Le code ci-dessous essaie donc plusieurs chemins
// de champs plausibles plutôt que de supposer une seule forme figée, et
// n'échoue jamais bruyamment si la forme réelle diffère de ce qui est
// anticipé ici — dans le pire cas, la liste renvoyée est simplement vide
// (comportement best-effort, jamais bloquant). À VÉRIFIER avec un vrai
// appel réseau avant de faire confiance aux résultats affichés.
async function getTeamInjuries(env, leagueId, season, teamId) {
  const covered = await getLeagueInjuryCoverage(env, leagueId, season);
  if (!covered) return []; // championnat non couvert par API-Football pour les blessures — silencieux, pas une erreur

  const cacheKey = "injuries:" + leagueId + ":" + season + ":" + teamId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const res = await apiFootballGet(env, "/injuries", { league: leagueId, season, team: teamId });
  const rawList = (res || []).map(r => ({
    player: r.player?.name || r.player?.player?.name || "Joueur inconnu",
    reason: r.player?.reason || r.reason || r.player?.type || r.type || "raison non précisée",
  })).filter(x => x.player !== "Joueur inconnu" || x.reason !== "raison non précisée");

  // Correctif (test réel du 30/07/2026, Liverpool-Chelsea) — l'API renvoie
  // une entrée par MATCH concerné par l'absence, pas une entrée unique par
  // joueur : un joueur blessé pour plusieurs semaines apparaissait donc
  // répété 3-4 fois d'affilée (une fois par match qu'il va manquer), ce qui
  // donnait l'impression trompeuse qu'il y avait bien plus de joueurs
  // absents qu'en réalité. Dédoublonnage sur la paire (joueur, raison).
  const seen = new Set();
  const list = rawList.filter(x => {
    const key = x.player + "|" + x.reason;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Cache 4h : la documentation indique une mise à jour de cette source
  // toutes les 4 heures, pas la peine de retaper l'API plus souvent.
  await cacheSet(env, cacheKey, list, 4 * 3600);
  return list;
}

// Correctif (15/08/2026) : LEAGUE_NAME_TO_FD contient des clés avec
// espaces/points ("2. bundesliga", "premier league"...), mais norm()
// retire aussi les espaces — ces clés ne pouvaient donc jamais matcher le
// résultat de norm(leagueName). "La Liga" fonctionnait par coïncidence
// (une clé sans espace "laliga" avait aussi été ajoutée en double), mais
// "2. Bundesliga", "Premier League", "Serie A", "Ligue 1/2" et
// "Championship" ne matchaient jamais — jamais détecté car pas retesté
// après le fix D1/D2. On normalise maintenant les clés du dictionnaire
// lui-même une seule fois, plutôt que de compter sur le fait de les avoir
// toutes tapées sans espace à la main.
const LEAGUE_NAME_TO_FD_NORM = Object.fromEntries(
  Object.entries(LEAGUE_NAME_TO_FD).map(([k, v]) => [norm(k), v])
);

async function fetchMainLeagueAveragesWithFallback(code, season) {
  const s = seasonToShortFD(season);
  try {
    const csv = await fetchTextFD(`https://www.football-data.co.uk/mmz4281/${s}/${code}.csv`);
    return averageMainLeagueCsv(csv);
  } catch (err) {
    const prevSeason = String(parseInt(season, 10) - 1);
    const prevS = seasonToShortFD(prevSeason);
    const csv = await fetchTextFD(`https://www.football-data.co.uk/mmz4281/${prevS}/${code}.csv`);
    const result = averageMainLeagueCsv(csv);
    result.seasonUsed = prevSeason;
    return result;
  }
}

async function getLeagueAverages(leagueName, country, season) {
  // Priorité au nom du championnat (résout correctement les pays à
  // plusieurs divisions — voir le commentaire au-dessus de LEAGUE_NAME_TO_FD).
  const nameKey = norm(leagueName);
  const directCode = LEAGUE_NAME_TO_FD_NORM[nameKey];
  if (directCode) {
    return fetchMainLeagueAveragesWithFallback(directCode, season);
  }

  const key = norm(country);
  if (TIERED_COUNTRIES_FD.has(key)) {
    // Pays à plusieurs divisions suivies, mais championnat non reconnu
    // dans LEAGUE_NAME_TO_FD : refuser explicitement plutôt que de deviner
    // l'élite au hasard (c'est exactement le bug qu'on vient de corriger).
    throw new Error("championnat \"" + leagueName + "\" non reconnu pour " + country +
      " (plusieurs divisions suivies pour ce pays sur football-data.co.uk, impossible de déterminer laquelle sans ambiguïté)");
  }

  const mainCode = Object.entries(MAIN_LEAGUES_FD).find(([k]) => norm(k) === key)?.[1];
  const extraCode = Object.entries(EXTRA_LEAGUES_FD).find(([k]) => norm(k) === key)?.[1];

  if (mainCode) {
    return fetchMainLeagueAveragesWithFallback(mainCode, season);
  }
  if (extraCode) {
    const csv = await fetchTextFD(`https://www.football-data.co.uk/new/${extraCode}.csv`);
    return averageExtraLeagueCsv(csv, season);
  }
  throw new Error("pays non reconnu pour football-data.co.uk: " + country);
}

function seasonToShortFD(season) {
  const y = parseInt(season, 10);
  const a = String(((y % 100) + 100) % 100).padStart(2, "0");
  const b = String(((y + 1) % 100 + 100) % 100).padStart(2, "0");
  return a + b;
}

async function fetchTextFD(url) {
  const res = await fetchT(url, {
    headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36" },
  });
  if (!res.ok) throw new Error("HTTP " + res.status + " sur " + url);
  return res.text();
}

function parseCsvLineFD(line) {
  return line.split(",");
}

function averageMainLeagueCsv(csv) {
  const lines = csv.split(/\r?\n/).filter(Boolean);
  if (!lines.length) throw new Error("fichier CSV vide");
  const header = parseCsvLineFD(lines[0]);
  const iH = header.indexOf("FTHG"), iA = header.indexOf("FTAG");
  if (iH < 0 || iA < 0) throw new Error("colonnes FTHG/FTAG introuvables");
  let sumH = 0, sumA = 0, n = 0;
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvLineFD(lines[i]);
    const h = parseFloat(cols[iH]), a = parseFloat(cols[iA]);
    if (isFinite(h) && isFinite(a)) { sumH += h; sumA += a; n++; }
  }
  if (!n) throw new Error("aucune ligne exploitable dans le CSV");
  return { lgH: sumH / n, lgA: sumA / n, matches: n };
}

function averageExtraLeagueCsv(csv, season) {
  const lines = csv.split(/\r?\n/).filter(Boolean);
  if (!lines.length) throw new Error("fichier CSV vide");
  const header = parseCsvLineFD(lines[0]);
  const iSeason = header.indexOf("Season"), iH = header.indexOf("HG"), iA = header.indexOf("AG");
  if (iSeason < 0 || iH < 0 || iA < 0) throw new Error("colonnes Season/HG/AG introuvables");
  let sumH = 0, sumA = 0, n = 0;
  for (let i = 1; i < lines.length; i++) {
    const cols = parseCsvLineFD(lines[i]);
    if (String(cols[iSeason]).trim() !== String(season).trim()) continue;
    const h = parseFloat(cols[iH]), a = parseFloat(cols[iA]);
    if (isFinite(h) && isFinite(a)) { sumH += h; sumA += a; n++; }
  }
  if (!n) throw new Error("aucun match trouvé pour la saison " + season + " dans ce fichier");
  return { lgH: sumH / n, lgA: sumA / n, matches: n };
}
