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
  THESTATSAPI_KEY: process.env.THESTATSAPI_KEY,
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

// Ajoute le 11/09/2026 -- reglement automatique du journal : recupere le
// score final d'un match TERMINE (statut "FT" chez API-Football) pour que
// le frontend puisse determiner tout seul si chaque marche loggue a gagne
// ou perdu, en reutilisant les memes fonctions f(i,j) du tableau MARKETS
// qui servent deja au calcul des probabilites -- zero nouvelle logique
// metier, juste une nouvelle source (score reel au lieu d'une distribution).
async function getMatchResult(env, leagueName, season, homeName, awayName, dateStr) {
  const league = await resolveLeague(env, leagueName, season);
  const homeTeam = await resolveTeam(env, homeName, league.leagueId, season);
  const awayTeam = await resolveTeam(env, awayName, league.leagueId, season);
  // Corrige le 12/09/2026 -- dateStr peut etre la date d'AJOUT au journal
  // cote frontend, pas forcement le vrai jour du coup d'envoi (analyse
  // faite la veille du match, confirme en direct sur Jeonbuk Motors vs FC
  // Seoul : pari logge le 11, match reellement joue le 12 -- recherche
  // exacte sur le 11 seul ne trouvait rien). Fenetre elargie (-1 a +2
  // jours) plutot qu'un jour unique et precis, pour rester robuste peu
  // importe quelle date exacte est envoyee.
  const d0 = new Date(dateStr + "T00:00:00Z");
  const fromStr = new Date(d0.getTime() - 1 * 86400000).toISOString().slice(0, 10);
  const toStr = new Date(d0.getTime() + 2 * 86400000).toISOString().slice(0, 10);
  const res = await apiFootballGet(env, "/fixtures", { league: league.leagueId, season, team: homeTeam.id, from: fromStr, to: toStr });
  if (!res || !res.length) throw new Error("aucun match trouve autour de cette date pour " + homeName);
  const fx = res.find(r => r.teams.home.id === awayTeam.id || r.teams.away.id === awayTeam.id);
  if (!fx) throw new Error("match contre " + awayName + " introuvable autour de cette date");
  const statusShort = fx.fixture.status.short;
  if (statusShort !== "FT" && statusShort !== "AET" && statusShort !== "PEN") {
    throw new Error("match pas encore termine (statut: " + statusShort + ")");
  }
  // homeGoals/awayGoals toujours dans le sens "equipe a domicile tapee par
  // l'utilisateur", peu importe l'ordre home/away retourne par l'API pour
  // CE fixture precis (rare mais possible en cas d'inversion domicile/
  // exterieur d'une saison a l'autre pour la meme paire d'equipes).
  const homeIsFixtureHome = fx.teams.home.id === homeTeam.id;
  return {
    homeGoals: homeIsFixtureHome ? fx.goals.home : fx.goals.away,
    awayGoals: homeIsFixtureHome ? fx.goals.away : fx.goals.home,
    status: statusShort,
  };
}

app.get("/api/result", async (req, res) => {
  try {
    const params = new URLSearchParams(req.query);
    const home = params.get("home"), away = params.get("away"), league = params.get("league"), date = params.get("date");
    const season = params.get("season") || String(new Date().getFullYear());
    const missing = ["home", "away", "league", "date"].filter(k => !params.get(k));
    if (missing.length) throw new Error("Parametres manquants: " + missing.join(", "));
    const result = await getMatchResult(env, league, season, home, away, date);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
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
      // Le pays tape (ou devine juste au-dessus via la sonde resolveLeague)
      // depart maintenant toute ambiguite de championnat (ex. "Serie B"
      // Italie vs Bresil) au lieu de dependre uniquement d'alias ajoutes
      // au coup par coup a chaque nouvelle collision decouverte.
      const league = await resolveLeague(env, leagueName, season, fsCountry);
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
      return await getXGViaTheStatsAPI(env, leagueName, homeName, awayName, fsCountry);
    })(),
    (async () => {
      // Meme departage par pays que pour resolveLeague ci-dessus, cote
      // The Odds API cette fois (ex. "Super Lig" Turquie vs "Superliga"
      // Danemark).
      try {
        const sportKey = await resolveSportKey(env, leagueName, fsCountry);
        return await getOddsCached(env, sportKey, homeName, awayName);
      } catch (err) {
        // Ajoute le 07/09/2026 -- championnat absent de The Odds API dans
        // sa totalite (ex. Colombie, confirme en direct : "championnat
        // introuvable: Primera A"), donc getOddsCached n'est jamais
        // atteinte. Dernier recours : OddsPapi comme source COMPLETE
        // (1N2 inclus), pas seulement en complement partiel comme pour les
        // championnats deja couverts par The Odds API.
        try {
          const oddsPapiOut = await getOddsFromOddsPapiOnly(env, homeName, awayName);
          return { odds: oddsPapiOut, warning: oddsPapiOut.warning };
        } catch (err2) {
          throw err; // erreur d'origine, plus parlante que celle d'OddsPapi seul
        }
      }
    })(),
    fsCountry ? (async () => {
      try {
        return await getLeagueAverages(leagueName, fsCountry, season);
      } catch (fdErr) {
        try {
          return await getLeagueAveragesTSA(env, leagueName, fsCountry, season);
        } catch (tsaErr) {
          throw fdErr; // on remonte l'erreur football-data (message plus etabli)
        }
      }
    })() : Promise.resolve(null),
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
  else warnings.push("xG (TheStatsAPI): " + xgResult.reason.message);

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
    injuries: (statsPart?.injuries?.home?.length || statsPart?.injuries?.away?.length) ? statsPart.injuries : (xgPart?.injuriesTSA || null), // Round 22 + complement TheStatsAPI (13/09) — {home: [...], away: [...]}, purement informatif
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
      return await getXGViaTheStatsAPI(env, leagueName, homeName, awayName, fsCountry);
    })(),
    sportKey ? getOddsCached(env, sportKey, homeName, awayName) : Promise.reject(new Error("paramètre 'sport' non fourni")),
    fsCountry ? (async () => {
      try {
        return await getLeagueAverages(leagueName, fsCountry, season);
      } catch (fdErr) {
        try {
          return await getLeagueAveragesTSA(env, leagueName, fsCountry, season);
        } catch (tsaErr) {
          throw fdErr; // on remonte l'erreur football-data (message plus etabli)
        }
      }
    })() : Promise.resolve(null),
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
  else warnings.push("xG (TheStatsAPI): " + xgResult.reason.message);

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
    injuries: (statsPart?.injuries?.home?.length || statsPart?.injuries?.away?.length) ? statsPart.injuries : (xgPart?.injuriesTSA || null), // Round 22 + complement TheStatsAPI (13/09)
    importCode: buildImportCode(homeName, awayName, statsPart, xgPart, oddsPart),
    warnings,
  };
}

function buildValues(stats, xg, odds) {
  return {
    a1: stats?.a1 ?? null, a2: stats?.a2 ?? null, a3: stats?.a3 ?? null, a4: stats?.a4 ?? null,
    b1: xg?.b1 ?? null, b2: xg?.b2 ?? null, b3: xg?.b3 ?? null, b4: xg?.b4 ?? null,
    xgConfiance: xg?.confiance ?? 1,
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


// Ajoute le 12/09/2026 -- meme schema de robustesse que apiFootballGet
// (throttle, cache appelant, 3 tentatives avec repli 2s/4s sur rate
// limit), adapte a TheStatsAPI : header Authorization Bearer au lieu de
// x-apisports-key, pas de nettoyage d'accents necessaire (non teste comme
// un probleme chez ce fournisseur, a surveiller si un cas apparait).
async function theStatsApiGet(env, path, qs) {
  await sleep(900); // Corrige le 12/09/2026 -- limite REELLE confirmee via les
  // en-tetes de reponse (x-ratelimit-limit: 12, fenetre de 10 secondes) : 12
  // requetes / 10s = ~830ms minimum entre chaque appel pour rester en dessous
  // en rythme soutenu. 900ms retenu (marge de securite), puisqu'un match
  // analyse peut enchainer jusqu'a ~15 appels (resolution championnat+2
  // equipes, puis jusqu'a 12 appels /stats) -- sans marge, la fenetre de 10s
  // serait depassee des le milieu d'une seule analyse.
  const url = "https://api.thestatsapi.com/api" + path + (qs ? "?" + new URLSearchParams(qs) : "");
  const MAX_ATTEMPTS = 3;
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const res = await fetchT(url, {
      headers: { "Authorization": "Bearer " + env.THESTATSAPI_KEY },
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      lastErr = new Error("TheStatsAPI HTTP " + res.status + " sur " + path + " — " + body.slice(0, 200));
      if (res.status === 429 && attempt < MAX_ATTEMPTS) {
        await sleep(2000 * attempt);
        continue;
      }
      throw lastErr;
    }
    const data = await res.json();
    return data.data;
  }
  throw lastErr;
}

async function apiFootballGet(env, path, qs) {
  // Pause avant chaque appel : filet de sécurité en plus du cache ci-dessus,
  // pour les appels qui ne peuvent pas être évités (premier lookup d'une
  // équipe/ligue jamais vue).
  await sleep(350); // Reduit de 1100ms le 05/09/2026 -- IP dediee confirmee, quota large (299/300 req/min), retrouve a 1100ms malgre un fix documente et teste le 29/07/2026 (tres probablement une regression, jamais une decision deliberee documentee). Filet de securite (3 tentatives, 2s/4s) inchange en cas de vrai rate limit.
  // Correctif (14/08/2026) : le paramètre "search" plante avec un accent
  // ("Vitória" -> 400 côté API-Football). On le nettoie ici, au point
  // d'entrée unique de tous les appels API-Football, plutôt que dans
  // chaque fonction appelante — corrige le problème pour toutes les
  // équipes/ligues accentuées d'un coup (Málaga, Deportivo La Coruña,
  // İstanbul Başakşehir...), pas seulement Vitória.
  // Corrige le 13/09/2026 (v2) -- le retrait SYSTEMATIQUE de la ponctuation
  // (v1, plus tot ce matin) evitait bien le crash "alpha-numeric only" sur
  // "1. FC Heidenheim", mais cassait "Ham-Kam" : leur base stocke le nom
  // AVEC le tiret pour l'equipe PREMIERE, alors que "HamKam" (tiret retire)
  // ne matche que les equipes jeunes/reserve/feminine ("HamKam U19",
  // "HamKam II", "HamKam W") -- lesquelles echouent ensuite la validation
  // ligue/saison, produisant un faux "nom ambigu". On tente desormais
  // D'ABORD avec la ponctuation intacte (juste les accents retires), et on
  // ne la retire QUE si ça echoue precisement sur cette erreur de
  // validation -- jamais preventivement.
  if (qs && typeof qs.search === "string") qs = { ...qs, search: stripDiacritics(qs.search) };
  const buildUrl = q => "https://v3.football.api-sports.io" + path + "?" + new URLSearchParams(q);

  // Nouvelle tentative automatique sur rate limit : confirmé par test direct
  // (curl depuis un poste normal) que la clé et le compte ont largement du
  // quota disponible (299/300 par minute, 7439/7500 par jour) — le blocage
  // vient donc de l'IP de sortie partagée des Workers Cloudflare, pas de la
  // clé elle-même. C'est un phénomène de bruit externe, temporaire par
  // nature, donc une nouvelle tentative avec pause a de bonnes chances de
  // passer sans jamais avoir touché à la clé ou au compte.
  async function tenter(qsActuel, dejaNettoye) {
    const url = buildUrl(qsActuel);
    const MAX_ATTEMPTS = 3;
    let lastErr = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      const res = await fetchT(url, {
        headers: { "x-apisports-key": env.APIFOOTBALL_KEY },
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        lastErr = new Error("API-Football HTTP " + res.status + " sur " + path + " — " + body.slice(0, 200));
        throw lastErr;
      }
      const data = await res.json();
      const isRateLimit = data.errors && Object.keys(data.errors).some(k =>
        /ratelimit/i.test(k) || /too many requests/i.test(String(data.errors[k])));
      const isSearchPunctuation = !dejaNettoye && data.errors?.search && /alpha-numeric/i.test(String(data.errors.search));
      if (isSearchPunctuation) {
        // Repli en dernier recours seulement : ponctuation retiree, un
        // seul essai supplementaire (pas de nouvelle boucle de rate-limit
        // imbriquee).
        const qsNettoye = { ...qsActuel, search: qsActuel.search.replace(/[^a-zA-Z0-9\s]/g, "") };
        return await tenter(qsNettoye, true);
      }
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
  return await tenter(qs, false);
}

// Ajoute le 12/09/2026 -- integration TheStatsAPI (remplace Understat pour
// le xG). Deux differences cle avec Understat : (1) couverture bien plus
// large (120+ championnats vs 6), mais (2) le xG n'est disponible qu'au
// niveau MATCH INDIVIDUEL (/matches/{id}/stats), jamais en agregat par
// equipe/saison -- confirme en direct, /teams/{id}/stats ne contient
// aucun champ xG. Consequence : contrairement a Understat (page unique par
// equipe), chaque match recent necessite son propre appel /stats, d'ou la
// limite a 6 matchs par cote (domicile/exterieur) plutot que l'historique
// complet de la saison, pour rester dans un budget de requetes raisonnable.
//
// Garde-fou de fraicheur : leur pipeline de traitement xG a un retard
// variable et TRES different d'un championnat/equipe a l'autre -- confirme
// en direct : Premier League et Gamba Osaka (J1 League) ont du xG le jour
// meme, mais Jeonbuk Hyundai Motors et Ulsan HD (K League 1, meme
// championnat) ont un retard de plus d'un mois. Le garde-fou est donc
// applique PAR EQUIPE (pas par championnat), et bloque purement et
// simplement le xG de ce cote-la (b1/b2 ou b3/b4 = null, jamais une valeur
// perimee affichee comme si elle etait fraiche) au-dela du seuil.
const THESTATSAPI_FRESHNESS_DAYS = 21;

// Corrige le 13/09/2026 -- certains championnats ont un nom sponsorise
// chez TheStatsAPI totalement different du nom generique/historique
// utilise dans l'app -- confirme en direct : "Primeira Liga" (Portugal)
// n'existe chez eux que sous "Liga Portugal Betclic", aucun mot en
// commun entre les deux, donc aucune tolerance de recherche (accents,
// inclusion partielle) ne peut combler cet ecart. Alias direct,
// necessaire au fil des championnats rencontres.
const THESTATSAPI_LEAGUE_ALIASES = {
  "primeira liga": "Liga Portugal Betclic",
  // Ajoute le 13/09/2026 -- "Major League Soccer" n'existe chez eux que
  // sous son sigle "MLS". Le filet de securite pays+type=league ne peut
  // pas rattraper ce cas : les USA ont PLUSIEURS championnats de type
  // "league" (MLS, NWSL, USL Championship, USL League One), donc le
  // filet refuse a raison de deviner -- alias explicite necessaire.
  "major league soccer": "MLS",
  // Ajoute le 13/09/2026 -- "Jupiler Pro League" (nom sponsorise saisi
  // dans l'app) n'existe chez eux que sous "Pro League" (sans sponsor).
  // Meme cas que le Portugal -- et la Belgique a aussi 2 championnats de
  // type league (Pro League + Challenger Pro League), le filet de
  // securite pays+type=league ne peut donc pas deviner seul non plus.
  "jupiler pro league": "Pro League",
  // Ajoute le 13/09/2026 -- "La Liga" (avec espace, saisi dans l'app)
  // vs "LaLiga" (sans espace, nom officiel chez eux) -- ecart minime
  // mais suffisant pour faire echouer leur recherche. Espagne a aussi 2
  // championnats de type league (LaLiga + LaLiga 2).
  "la liga": "LaLiga",
  // Ajoute le 13/09/2026 -- "Segunda División" (nom officiel API-Football,
  // utilise dans le champ Championnat de l'app) n'existe chez TheStatsAPI
  // que sous "LaLiga 2".
  "segunda división": "LaLiga 2",
  // Ajoute le 13/09/2026 -- "Liga Profesional Argentina" (saisi) n'existe
  // chez eux que sous "Liga Profesional de Fútbol" (sans le pays, "de
  // Fútbol" au lieu de "Argentina").
  "liga profesional argentina": "Liga Profesional de Fútbol",
};

async function resolveTheStatsAPICompetition(env, leagueName, countryHint) {
  const cacheKey = "tsa_comp:" + leagueName.toLowerCase().trim() + ":" + (countryHint || "").toLowerCase().trim();
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  const nomRecherche = THESTATSAPI_LEAGUE_ALIASES[leagueName.toLowerCase().trim()] || leagueName;
  let res = await theStatsApiGet(env, "/football/competitions", { search: nomRecherche });
  // Filet de securite generique le 13/09/2026 -- pour tout futur cas de
  // renommage sponsorise non encore ajoute a THESTATSAPI_LEAGUE_ALIASES
  // (ex. Primeira Liga -> Liga Portugal Betclic) : si la recherche par
  // nom echoue mais qu'on connait le pays (countryHint), on retente en
  // filtrant uniquement par pays + type=league. Utilise seulement si un
  // SEUL championnat de type league existe pour ce pays -- plusieurs pays
  // ont 1ere ET 2eme division toutes deux typees "league" (confirme :
  // Portugal a "Liga Portugal Betclic" ET "Liga Portugal 2"), dans ce cas
  // deviner serait pire que d'echouer proprement.
  if ((!res || !res.length) && countryHint) {
    const parPays = await theStatsApiGet(env, "/football/competitions", { country: countryHint, type: "league", per_page: 10 });
    if (parPays && parPays.length === 1) res = parPays;
  }
  if (!res || !res.length) throw new Error("championnat introuvable chez TheStatsAPI: " + leagueName);
  // Corrige le 12/09/2026 -- collision confirmee en direct : "Premier
  // League" existe chez TheStatsAPI en Angleterre, Canada, Egypte,
  // Israel, Russie et Ukraine -- leur recherche classait l'Angleterre
  // seulement 4e, donc res[0] tombait sur le Canada (ou "Arsenal"
  // n'existe evidemment pas). Meme mecanisme de departage par pays que
  // pour resolveLeague (API-Football) et resolveSportKey (The Odds API).
  let comp = res[0];
  // Corrige le 13/09/2026 -- le departage par pays ne suffit pas quand
  // l'ambiguite est DANS le meme pays : "Bundesliga" matchait "2.
  // Bundesliga" (par inclusion partielle) ET "Bundesliga" (allemagne les
  // deux) -- confirme en direct sur RB Leipzig. Le departage par pays
  // choisissait arbitrairement le premier des deux (la 2e division,
  // apparue en premier dans leurs resultats), jamais rattrape puisque
  // les deux partagent le meme pays. Priorite absolue a une correspondance
  // de nom EXACTE avant tout departage par pays.
  const nomExact = res.find(c => (c.name || "").toLowerCase().trim() === nomRecherche.toLowerCase().trim());
  if (nomExact) {
    comp = nomExact;
  } else if (countryHint) {
    const ch = countryHint.toLowerCase().trim();
    const match = res.find(c => (c.country || "").toLowerCase().trim() === ch);
    if (match) comp = match;
  }
  await cacheSet(env, cacheKey, comp, 2592000); // 30 jours
  return comp;
}

// Corrige le 13/09/2026 -- une table d'alias par club (comme celle qui
// existait ici avant ce correctif) demande une correction manuelle a
// chaque nouveau club rencontre avec caractere special. Solution
// generale : au lieu de compter sur leur recherche (qui exige une
// correspondance exacte caractere par caractere -- "Wisla" ne matche pas
// "Wisła", le l-barre polonais n'est PAS un accent detachable, contrairement
// a e/a/o accentues geres par stripDiacritics), on recupere la liste
// COMPLETE des equipes du championnat une seule fois (mise en cache 30j,
// quasi gratuit ensuite), et on compare nous-memes apres neutralisation
// des accents ET des lettres speciales des deux cotes.
const LETTRES_SPECIALES = {
  "ł": "l", "Ł": "L", "ø": "o", "Ø": "O", "ß": "ss",
  "þ": "th", "Þ": "Th", "đ": "d", "Đ": "D", "ı": "i",
  // Ajoute le 13/09/2026 -- "æ" (scandinave) confirme en direct sur "FC
  // Nordsjælland", saisi "Nordsjaelland" (epele) dans l'app.
  "æ": "ae", "Æ": "AE",
};
function normaliseNomEquipe(s) {
  let out = (s || "");
  for (const [special, ascii] of Object.entries(LETTRES_SPECIALES)) out = out.split(special).join(ascii);
  out = out.normalize("NFD").replace(/[\u0300-\u036f]/g, ""); // accents detachables (é,á,ñ...)
  return out.toLowerCase().replace(/[^a-z0-9]/g, "");
}

// Ajoute le 13/09/2026 -- au-dela des accents/lettres speciales (deja
// geres par normaliseNomEquipe), certains clubs ont une abreviation de
// ville sans aucune sous-chaine commune avec le nom complet -- confirme
// en direct : "LA Galaxy" (chez eux) vs "Los Angeles Galaxy" (saisi),
// "losangelesgalaxy" ne contient litteralement pas "lagalaxy". Alias
// ponctuel en dernier recours, apres l'echec de la comparaison generale.
const THESTATSAPI_TEAM_ALIASES = {
  "losangelesgalaxy": "LA Galaxy",
  // Ajoute le 13/09/2026 -- "Hammarby FF" (saisi) vs "Hammarby IF" (nom
  // officiel chez eux) -- suffixe suedois different (Idrottsforening vs
  // Fotbollsforening), aucune sous-chaine commune sur ces 2 lettres.
  "hammarbyff": "Hammarby IF",
};

async function resolveTheStatsAPITeam(env, competitionId, teamName) {
  const cacheKey = "tsa_teamlist:" + competitionId;
  let allTeams = await cacheGet(env, cacheKey);
  if (!allTeams) {
    const res = await theStatsApiGet(env, "/football/teams", { competition_id: competitionId, per_page: 100 });
    allTeams = res || [];
    await cacheSet(env, cacheKey, allTeams, 2592000); // 30 jours
  }
  const target = normaliseNomEquipe(teamName);
  let team = allTeams.find(t => {
    const n = normaliseNomEquipe(t.name);
    return n === target || n.includes(target) || target.includes(n);
  });
  if (!team && THESTATSAPI_TEAM_ALIASES[target]) {
    const alias = normaliseNomEquipe(THESTATSAPI_TEAM_ALIASES[target]);
    team = allTeams.find(t => normaliseNomEquipe(t.name) === alias);
  }
  if (!team) throw new Error("équipe introuvable chez TheStatsAPI: " + teamName);
  return team;
}

async function getRecentXGMatches(env, competitionId, teamId, isHomeSide) {
  // Cache court (1h, comme getRecentFixtures cote API-Football) : la liste
  // de matchs recents change a chaque journee jouee.
  const cacheKey = "tsa_matches:" + competitionId + ":" + teamId + ":" + (isHomeSide ? "h" : "a");
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  const res = await theStatsApiGet(env, "/football/matches", { team_id: teamId, competition_id: competitionId, status: "finished", per_page: 50 });
  const matches = (res || [])
    .filter(m => m.xg_available && (isHomeSide ? m.home_team.id === teamId : m.away_team.id === teamId))
    .sort((a, b) => new Date(b.utc_date) - new Date(a.utc_date))
    .slice(0, 6);
  await cacheSet(env, cacheKey, matches, 3600);
  return matches;
}

async function getXGForSide(env, competitionId, teamId, isHomeSide) {
  const matches = await getRecentXGMatches(env, competitionId, teamId, isHomeSide);
  if (!matches.length) return { xgFor: null, xgAgainst: null, warning: "aucun match avec xG disponible" };
  const mostRecentDate = new Date(matches[0].utc_date);
  const daysSince = (Date.now() - mostRecentDate.getTime()) / 86400000;
  const forVals = [], againstVals = [];
  for (const m of matches) {
    const statsCacheKey = "tsa_stats:" + m.id;
    let stats = await cacheGet(env, statsCacheKey);
    if (!stats) {
      const res = await theStatsApiGet(env, "/football/matches/" + m.id + "/stats", null);
      stats = res;
      await cacheSet(env, statsCacheKey, stats, 2592000); // match termine, xG ne change jamais -- cache long
    }
    const xg = stats?.overview?.expected_goals?.all;
    if (!xg) continue;
    if (isHomeSide) { forVals.push(xg.home); againstVals.push(xg.away); }
    else { forVals.push(xg.away); againstVals.push(xg.home); }
  }
  if (!forVals.length) return { xgFor: null, xgAgainst: null, warning: "stats xG indisponibles malgré xg_available=true", confiance: 1 };
  const avg = arr => arr.reduce((s, v) => s + v, 0) / arr.length;
  // Corrige le 13/09/2026 -- sur demande explicite : le seuil de fraicheur
  // (21j) ne bloque plus le xG, il l'accompagne d'un avertissement --
  // meme philosophie que le badge "echantillon faible" existant ailleurs
  // dans l'app (prevenir, jamais cacher une donnee reelle). Confirme en
  // direct sur FC Utrecht (Eredivisie) : un seul match a l'exterieur
  // disponible, vieux d'1 jour de plus que l'ancien seuil strict -- perdre
  // cette donnee etait plus genant que de l'afficher avec prudence.
  const warning = daysSince > THESTATSAPI_FRESHNESS_DAYS
    ? "xG basé sur " + forVals.length + " match(s), dont le plus récent date de " + Math.round(daysSince) + " jours (seuil habituel " + THESTATSAPI_FRESHNESS_DAYS + "j) — fraîcheur limitée"
    : null;
  // Ajoute le 13/09/2026 -- sur demande explicite : le xG perime ne doit
  // plus peser a 100% dans le calcul final comme une donnee fraiche.
  // Confiance = 1.0 jusqu'au seuil (21j), puis decroit lineairement,
  // plancher a 0.3 (jamais totalement ignore, juste moins pese) atteint a
  // 51j. Formule choisie, pas mesuree par backtest -- a affiner si les
  // resultats s'averent decevants une fois assez de matchs analyses avec.
  const confiance = daysSince <= THESTATSAPI_FRESHNESS_DAYS
    ? 1
    : Math.max(0.3, 1 - (daysSince - THESTATSAPI_FRESHNESS_DAYS) / 30);
  return { xgFor: avg(forVals), xgAgainst: avg(againstVals), warning, confiance };
}

// Ajoute le 13/09/2026 -- complement aux blessures API-Football (Round
// 22, limitees aux grands championnats) : TheStatsAPI couvre 116+
// championnats pour /injuries-suspensions, comble donc le meme trou que
// pour le xG sur les championnats non couverts par API-Football. Meme
// forme de sortie ({player, reason}) que l'existant -- reutilise tel
// quel cote frontend, aucun changement necessaire la-bas.
async function getPlayerName(env, playerId) {
  const cacheKey = "tsa_player:" + playerId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  let name = playerId; // repli si l'appel echoue -- jamais bloquant
  try {
    const res = await theStatsApiGet(env, "/football/players/" + playerId, null);
    if (res?.name) name = res.name;
  } catch (err) {
    // best-effort
  }
  await cacheSet(env, cacheKey, name, 2592000); // 30 jours, un nom de joueur ne change pas
  return name;
}

async function getInjuriesForTeamTSA(env, teamId) {
  const cacheKey = "tsa_injuries:" + teamId;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;
  let list = [];
  try {
    const res = await theStatsApiGet(env, "/football/teams/" + teamId + "/injuries-suspensions", null);
    const items = [
      ...(res?.injuries || []).filter(i => i.active).map(i => ({ playerId: i.player_id, reason: (i.reason || "blessure").replace(/_/g, " ") })),
      ...(res?.suspensions || []).filter(s => s.active).map(s => ({ playerId: s.player_id, reason: "suspension (" + (s.matches || 1) + " match" + ((s.matches || 1) > 1 ? "s" : "") + ")" })),
    ];
    for (const it of items) {
      list.push({ player: await getPlayerName(env, it.playerId), reason: it.reason });
    }
  } catch (err) {
    // best-effort -- jamais bloquant, juste une liste vide en cas d'echec
  }
  await cacheSet(env, cacheKey, list, 3600); // 1h, une blessure peut survenir a tout moment
  return list;
}

async function getXGViaTheStatsAPI(env, leagueName, homeName, awayName, fsCountry) {
  const warnings = [];
  const comp = await resolveTheStatsAPICompetition(env, leagueName, fsCountry);
  const homeTeam = await resolveTheStatsAPITeam(env, comp.id, homeName);
  const awayTeam = await resolveTheStatsAPITeam(env, comp.id, awayName);
  const homeSide = await getXGForSide(env, comp.id, homeTeam.id, true);
  const awaySide = await getXGForSide(env, comp.id, awayTeam.id, false);
  if (homeSide.warning) warnings.push("xG domicile (TheStatsAPI): " + homeSide.warning);
  if (awaySide.warning) warnings.push("xG extérieur (TheStatsAPI): " + awaySide.warning);
  // Confiance globale = la plus faible des deux cotes (domicile/exterieur)
  // -- le maillon le plus faible determine la confiance globale du match,
  // pas une moyenne qui masquerait un cote tres perime par un cote frais.
  const confiance = Math.min(homeSide.confiance ?? 1, awaySide.confiance ?? 1);
  // Reutilise homeTeam.id/awayTeam.id deja resolus juste au-dessus --
  // aucun appel de resolution supplementaire, juste la recuperation des
  // blessures/suspensions pour ces memes equipes.
  let injuriesTSA = null;
  try {
    const [homeInj, awayInj] = await Promise.all([
      getInjuriesForTeamTSA(env, homeTeam.id),
      getInjuriesForTeamTSA(env, awayTeam.id),
    ]);
    if (homeInj.length || awayInj.length) injuriesTSA = { home: homeInj, away: awayInj };
  } catch (err) {
    // best-effort -- ne bloque jamais le xG si les blessures echouent
  }
  return {
    b1: homeSide.xgFor, b2: homeSide.xgAgainst,
    b3: awaySide.xgFor, b4: awaySide.xgAgainst,
    confiance,
    injuriesTSA,
    warnings,
  };
}

// Ajoute le 07/09/2026 -- certains noms de championnat existent a

// l'identique dans plusieurs pays (ex. "Serie B" en Italie ET au Bresil,
// confirme en direct sur Palermo vs Sampdoria : les deux obtenaient un
// score parfaitement egal dans resolveLeague -- nom exact + type League +
// saison presente -- et l'ordre de l'API-Football (Bresil avant Italie
// dans la reponse /leagues) tranchait au hasard, choisissant le mauvais
// pays sans aucun signal d'erreur). Cette table ne sert qu'a departager
// une egalite parfaite : un petit bonus de score est applique si le pays
// correspond a celui attendu pour ce nom de championnat.
// Table de repli statique : ne sert que si l'utilisateur laisse le champ
// "Pays" vide. Quand il est rempli, c'est ce pays-la qui prime toujours
// (voir countryHint dans resolveLeague ci-dessous) -- generique pour tout
// futur championnat ambigu, pas seulement "Serie B".
const LEAGUE_COUNTRY_HINTS = {
  "serieb": "Italy",
};
async function resolveLeague(env, leagueName, season, countryHint) {
  // L'ID d'une ligue ne change jamais — cache long (30 jours). La cle
  // inclut desormais le pays indice : sans ca, la premiere personne (ou le
  // premier essai) a resoudre "Serie B" figerait le resultat en cache pour
  // 30 jours, peu importe le pays demande ensuite par quelqu'un d'autre.
  const chRaw = (countryHint || "").trim();
  const cacheKey = "league:" + norm(leagueName) + ":" + norm(chRaw);
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  // Ajoute le 07/09/2026 -- le champ Championnat de l'app affiche le nom
  // suivi du pays ("Süper Lig — Turkey", tiret cadratin inclus). Envoyer ce
  // texte tel quel a /leagues (recherche libre API-Football) renvoyait
  // ZERO resultat (confirme en direct : "Süper Lig — Turkey" => 0 reponse,
  // "Süper Lig" seul => 4 reponses dont la bonne) -- le moteur de
  // recherche d'API-Football ne tolere pas ce suffixe compose. On envoie
  // desormais uniquement la partie avant le tiret cadratin (ou le tiret
  // simple/double en repli) a la recherche ; countryHint (deja en place
  // ci-dessus) se charge ensuite de departager les homonymes que ce nom
  // nettoye peut faire remonter (ex. "Süper Lig" existe aussi en Serbie,
  // Moldavie, Slovaquie).
  const searchName = leagueName.split(/[—–-]/)[0].trim() || leagueName;
  // Ajoute le 13/09/2026 -- paradoxe decouvert en direct sur "2. Bundesliga"
  // (id API-Football 79) : leur nom officiel CONTIENT un point, mais leur
  // champ de recherche REJETTE tout signe de ponctuation (meme erreur que
  // le correctif du jour sur "1. FC Heidenheim") -- retirer le point pour
  // passer la validation casse alors la correspondance avec leur propre
  // nom stocke, qui lui garde le point. Impossible a resoudre par la
  // recherche dans ce cas precis : alias direct par ID (fixe, ne change
  // jamais) pour les rares championnats dans ce cas. Cle sans espace
  // (norm() retire aussi les espaces, pas seulement la ponctuation).
  const LEAGUE_ID_ALIASES = { "2bundesliga": 79 };
  const idAlias = LEAGUE_ID_ALIASES[norm(searchName)];
  const res = idAlias
    ? await apiFootballGet(env, "/leagues", { id: idAlias })
    : await apiFootballGet(env, "/leagues", { search: searchName });
  if (!res || !res.length) throw new Error("championnat introuvable: " + leagueName);

  // La recherche peut renvoyer plusieurs entrées proches (ex. "Liga MX"
  // ET "Liga MX Femenil"). On priorise : nom exact > type "League"
  // (pas Cup) > présence de la saison demandée > pays attendu — le champ
  // "Pays" tape par l'utilisateur prime sur la table statique de repli.
  const n = norm(leagueName);
  const effectiveCountryHint = chRaw || LEAGUE_COUNTRY_HINTS[n];
  const score = r => {
    let s = 0;
    if (norm(r.league.name) === n) s += 100;
    if (r.league.type === "League") s += 10;
    if ((r.seasons || []).some(x => String(x.year) === String(season))) s += 1;
    if (effectiveCountryHint && norm(r.country?.name || "") === norm(effectiveCountryHint)) s += 50;
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
  let res = await apiFootballGet(env, "/teams", { search: teamName });
  if ((!res || !res.length) && TEAM_SEARCH_ALIASES) {
    // Ajoute le 07/09/2026 -- certains clubs portent, dans l'usage courant,
    // un nom qui ne partage RIEN avec leur nom officiel API-Football ("CD
    // Tolima" vs "Deportes Tolima" -- confirme en direct sur Llaneros vs CD
    // Tolima, Colombie : la recherche initiale ne renvoie ZERO resultat,
    // pas juste le mauvais championnat, donc le retry premier-mot plus bas
    // dans cette fonction n'est jamais atteint). Contrairement a
    // TEAM_NAME_ALIASES (comparaison de texte normalise, utilisee pour le
    // matching des cotes), cette table sert de terme de recherche a
    // proprement envoyer a l'API -- d'ou une table separee, avec des
    // valeurs qui restent lisibles (espaces conserves).
    const nTeam = norm(teamName);
    const aliasKey = Object.keys(TEAM_SEARCH_ALIASES).find(k => nTeam.includes(k) || k.includes(nTeam));
    if (aliasKey) {
      try {
        const res2 = await apiFootballGet(env, "/teams", { search: TEAM_SEARCH_ALIASES[aliasKey] });
        if (res2 && res2.length) res = res2;
      } catch (errAlias) {
        // best-effort : si cet essai echoue aussi, on retombe sur le
        // message d'erreur habituel juste en dessous.
      }
    }
  }
  if (!res || !res.length) throw new Error("équipe introuvable: " + teamName);

  let candidates = res;
  try {
    const validIds = await getLeagueTeamIds(env, leagueId, season);
    if (validIds.size) {
      let inLeague = res.filter(r => validIds.has(r.team.id));
      // Ajoute le 07/09/2026 -- certains clubs sont enregistres cote
      // API-Football sous une abreviation qui ne partage aucun mot complet
      // avec le nom usuel ("Argentinos JRS" vs "Argentinos Juniors" -- leur
      // moteur de recherche ne fait aucun rapprochement flou entre "JRS" et
      // "Juniors", confirme en direct : chercher le nom complet ne
      // remontait que l'equipe reserve, jamais l'equipe premiere). Avant de
      // conclure a un homonyme, on retente avec le PREMIER mot seul du nom
      // tape, qui suffit generalement a retrouver le club meme quand le
      // reste du nom differe -- best-effort, jamais pire que l'ancien
      // comportement si ca ne trouve rien de plus.
      if (!inLeague.length) {
        const firstWord = teamName.trim().split(/\s+/)[0];
        if (firstWord && firstWord.length >= 4 && norm(firstWord) !== norm(teamName)) {
          try {
            const res2 = await apiFootballGet(env, "/teams", { search: firstWord });
            if (res2 && res2.length) {
              inLeague = res2.filter(r => validIds.has(r.team.id));
            }
          } catch (err2) {
            // best-effort : si ce second essai echoue, on retombe sur le
            // message d'ambiguite habituel juste en dessous.
          }
        }
      }
      // Ajoute le 12/09/2026 -- troisieme tentative via TEAM_SEARCH_ALIASES,
      // pour le cas ou la recherche initiale renvoie bien des resultats
      // (contrairement a Tolima) mais AUCUN dans la bonne ligue -- typique
      // d'un club dont l'equipe premiere est enregistree sous un nom sans
      // aucun rapport avec le nom d'usage (ex. "Guimaraes" -> equipes B/
      // U23/U19/feminine seulement, l'equipe premiere est "Vitoria SC").
      // Le premier essai (recherche vide) et celui-ci (recherche non vide
      // mais mauvaise ligue) sont deux echecs differents, tous deux geres
      // par la meme table d'alias.
      if (!inLeague.length) {
        const nTeam2 = norm(teamName);
        const aliasKey2 = Object.keys(TEAM_SEARCH_ALIASES).find(k => nTeam2.includes(k) || k.includes(nTeam2));
        if (aliasKey2) {
          try {
            const res3 = await apiFootballGet(env, "/teams", { search: TEAM_SEARCH_ALIASES[aliasKey2] });
            if (res3 && res3.length) {
              inLeague = res3.filter(r => validIds.has(r.team.id));
            }
          } catch (err3) {
            // best-effort : si ce troisieme essai echoue, on retombe sur le
            // message d'ambiguite habituel juste en dessous.
          }
        }
      }
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
// Ajoute le 07/09/2026 -- plutot que de continuer a ajouter un alias par
// collision decouverte au fil de l'eau (Turquie/Danemark, Italie/Bresil
// ce soir), on utilise desormais le champ "Pays" deja rempli par
// l'utilisateur (fsCountry) comme departage generique : quand plusieurs
// championnats correspondent au nom tape, on prefere celui dont le titre
// The Odds API contient le pays indique. Les alias statiques restent en
// filet de securite pour les cas ou le champ Pays est laisse vide, ou pour
// les noms qui ne partagent aucun mot avec leur titre officiel (EPL...).
async function resolveSportKey(env, leagueName, countryHint) {
  // Cache long (30 jours), même logique que resolveLeague. La cle inclut
  // desormais le pays indice : "Serie B" + "Italy" et "Serie B" sans pays
  // ne doivent pas partager la meme entree de cache, sous peine de servir
  // une resolution figee sur le premier pays demande par n'importe quel
  // utilisateur.
  const ch = norm(countryHint || "");
  const cacheKey = "sportkey:" + norm(leagueName) + ":" + ch;
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const res = await fetchT("https://api.the-odds-api.com/v4/sports?apiKey=" + env.ODDS_API_KEY);
  if (!res.ok) throw new Error("HTTP " + res.status + " (liste des sports) — clé longueur=" + (env.ODDS_API_KEY || "").length);
  const list = await res.json();
  // Correctif du 07/09/2026 (bis) -- le champ Championnat de l'app peut
  // afficher le nom SEUL ("Süper Lig") ou SUIVI du pays ("Süper Lig —
  // Turkey") selon le chemin emprunte pour le remplir (selection directe
  // vs lien "changer"). L'alias precedent etait code en dur sur le format
  // avec pays colle ("superligturkey"), donc des que l'utilisateur voit le
  // champ sans le pays, l'alias ne matchait plus DU TOUT et "Süper Lig"
  // retombait sur l'ancien bug de collision avec le Danemark (confirme en
  // direct : Besiktas vs Erzurumspor, "Süper Lig" seul → introuvable, alors
  // que "Süper Lig — Turkey" fonctionnait). On nettoie desormais le nom
  // (tout ce qui suit un tiret) AVANT de calculer n, pour que les deux
  // formats du champ produisent la meme cle -- alignes sur le meme
  // nettoyage deja applique cote API-Football dans resolveLeague.
  const baseLeagueName = leagueName.split(/[—–-]/)[0].trim() || leagueName;
  const n = norm(baseLeagueName);
  // Alias : certains championnats ont un titre The Odds API qui ne partage
  // aucun mot avec le nom API-Football. Ex. "Premier League" cote "EPL" —
  // aucune inclusion mutuelle possible. On force la cle dans ces cas.
  const ALIAS = {
    "premierleague": "soccer_epl",
    "laliga": "soccer_spain_la_liga",
    "seriea": "soccer_italy_serie_a",
    "bundesliga": "soccer_germany_bundesliga",
    "ligue1": "soccer_france_ligue_one",
    "primeiraliga": "soccer_portugal_primeira_liga",
    "eredivisie": "soccer_netherlands_eredivisie",
    "superlig": "soccer_turkey_super_league",
    "serieb": "soccer_italy_serie_b",
    "ligaprofesional": "soccer_argentina_primera_division",
    // Ajoute le 11/09/2026 -- "K League 1" (Coree du Sud) contient
    // litteralement "league1" comme sous-chaine une fois normalise
    // ("kleague1"), collision avec "League 1" (Angleterre, "league1").
    // Contrairement aux collisions precedentes (Turquie/Danemark,
    // Italie/Bresil), countryHint ne peut PAS departager ce cas : le
    // titre officiel "K League 1" ne mentionne "Korea" nulle part dans
    // son propre texte -- confirme en direct sur Bucheon FC 1995 vs Jeju
    // United FC.
    "kleague1": "soccer_korea_kleague1",
    // Ajoute le 13/09/2026 -- "Jupiler Pro League" (nom sponsorise saisi
    // dans l'app) n'existe chez The Odds API que sous "Belgium First Div"
    // -- confirme en direct, aucun mot en commun entre les deux noms.
    "jupilerproleague": "soccer_belgium_first_div",
    // Ajoute le 13/09/2026 -- "2. Bundesliga" (saisi, chiffre au debut)
    // vs "Bundesliga 2" (titre officiel chez The Odds API, chiffre a la
    // fin) -- ordre des mots inverse, meme famille de collision que
    // Turku PS/TPS Turku plus tot ce soir.
    "2bundesliga": "soccer_germany_bundesliga2"
  };
  // Correctif du 07/09/2026 -- la premiere version de ce patch desactivait
  // l'alias des qu'un pays etait fourni, en partant du principe que le
  // countryHint suffirait. Faux : le champ Championnat de l'app inclut
  // deja le pays dans son propre texte ("Sueper Lig -- Turkey"), donc une
  // fois normalise il ne matche plus AUCUN titre The Odds API par simple
  // inclusion -- sans l'alias pour rattraper ce cas, plus rien ne
  // fonctionnait (confirme en direct sur Besiktas vs Erzurumspor, qui
  // marchait avant ce soir). L'alias reste donc verifie inconditionnellement
  // en premier ; le countryHint ne sert qu'a departager les cas que
  // l'alias ne couvre pas encore.
  // Correctif du 07/09/2026 (ter) -- meme cause que les deux precedents
  // correctifs ce soir, une troisieme fois : le nom de base peut lui-meme
  // deja contenir le pays ("Liga Profesional Argentina", nom officiel API-
  // Football), donc une cle d'alias exacte ("ligaprofesional") ne matche
  // plus des que l'autocomplete choisit ce nom complet plutot que la
  // version courte. Plutot que de rajouter une cle par variante de texte a
  // chaque nouvelle collision (ce qui ne finira jamais), la recherche
  // d'alias tolere desormais l'inclusion dans les deux sens, comme le reste
  // de la logique de matching de ce fichier.
  const aliasKey = ALIAS[n] ? n : Object.keys(ALIAS).find(k => n.includes(k) || k.includes(n));
  if (aliasKey) {
    const forced = list.find(s => s.key === ALIAS[aliasKey]);
    if (forced) { await cacheSet(env, cacheKey, forced.key, 2592000); return forced.key; }
  }
  const candidates = list.filter(s => s.group === "Soccer" && (norm(s.title).includes(n) || n.includes(norm(s.title))));
  let match = null;
  if (candidates.length) {
    // Ajoute le 12/09/2026 -- countryHint echouait sur "Switzerland" vs
    // "Swiss Superleague" : le titre officiel utilise le demonyme (l'
    // adjectif national), pas le nom du pays tel que tape dans le champ
    // Pays -- confirme en direct sur FC Lugano vs BSC Young Boys, ou les
    // 4 candidats "Super League" (Chine/Grece/Suisse/Turquie) ne
    // pouvaient etre departages puisque aucun ne contenait "switzerland".
    // Table volontairement minimale : etendue au fil des cas rencontres,
    // pas une liste exhaustive de tous les demonymes du monde.
    const DEMONYMS = { switzerland: "swiss", england: "english", netherlands: "dutch", france: "french", germany: "german", spain: "spanish", italy: "italian", scotland: "scottish", wales: "welsh" };
    const chAlt = DEMONYMS[ch] || null;
    if (ch) match = candidates.find(s => { const t = norm(s.title); return t.includes(ch) || (chAlt && t.includes(chAlt)); }) || null;
    if (!match) match = (ALIAS[n] && candidates.find(s => s.key === ALIAS[n])) || candidates[0];
  }
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
// Corrige le 07/09/2026 -- certains clubs ont un nom court qui n'est PAS
// un prefixe de leur nom complet, contrairement a la quasi-totalite des
// clubs francais (Lens/RC Lens, Nice/OGC Nice...). "Rennes" vs "Stade
// RENNAIS FC" est le premier cas trouve (forme adjectivale, pas un
// prefixe) -- confirme en direct : Angers vs Rennes introuvable chez
// OddsPapi malgre l'existence reelle du match. Petite liste d'alias
// explicites, extensible si d'autres cas similaires apparaissent,
// plutot qu'un algorithme flou plus risque en faux positifs.
const TEAM_NAME_ALIASES = {
  "rennes": ["rennais"],
  // Ajoute le 07/09/2026 -- effet de bord du correctif TEAM_SEARCH_ALIASES
  // juste en dessous : une fois les stats corrigees, le champ affiche
  // "Deportes Tolima" (nom officiel API-Football), mais OddsPapi connait ce
  // club sous "CD Tolima" (confirme dans leur flux fixtures) -- deux SOURCES
  // DIFFERENTES avec des conventions de nom differentes pour le meme club.
  // teamNameMatches() (utilisee pour le matching des cotes, The Odds API et
  // OddsPapi) a besoin de son propre alias, independant de celui de
  // resolveTeam ci-dessous qui ne sert qu'a la recherche API-Football.
  "tolima": ["cdtolima"],
  // Ajoute le 12/09/2026 -- "QPR" (3 lettres, sigle usuel) ne partage pas
  // assez de caracteres consecutifs avec "Queens Park Rangers" (nom
  // officiel The Odds API) pour matcher via le test des 5 premiers
  // caracteres -- confirme en direct sur West Brom vs QPR.
  "qpr": ["queensparkrangers"],
  // Ajoute le 12/09/2026 -- "Turku PS" vs "TPS Turku" (The Odds API) n'est
  // pas juste un ordre de mots inverse : "TPS" est un seul token chez The
  // Odds API, mais "Turku PS" se decoupe en "turku"+"ps" cote saisie
  // utilisateur -- deux ensembles de mots differents, que le tri ajoute
  // juste avant ne peut pas reconcilier. Alias direct sur les deux formes
  // completes plutot que sur un mot isole.
  "turkups": ["tpsturku", "turunpalloseura"],
  // Ajoute le 12/09/2026 -- OddsPapi utilise "Young Boys Bern" plutot que
  // "BSC Young Boys" -- confirme en direct sur FC Lugano vs BSC Young Boys.
  "youngboys": ["youngboysbern"],
  // Ajoute le 12/09/2026 -- meme cas que Tolima (07/09) : une fois les
  // stats corrigees via TEAM_SEARCH_ALIASES, le champ affichera "Vitoria
  // SC" (nom officiel API-Football/The Odds API), qui ne partage pas
  // assez de caracteres avec "Guimaraes" (nom d'usage) pour matcher --
  // ajoute ici PREVENTIVEMENT, avant que le meme effet de bord ne se
  // reproduise comme pour Tolima ce soir.
  "guimaraes": ["vitoriasc"],
};
// Voir usage detaille dans resolveTeam ci-dessus : terme de recherche
// alternatif a envoyer a l'API-Football quand la recherche du nom tel que
// saisi ne renvoie strictement aucun resultat (pas juste le mauvais
// championnat -- ce cas est deja gere par le retry premier-mot).
const TEAM_SEARCH_ALIASES = {
  "tolima": "Deportes Tolima",
  // Ajoute le 12/09/2026 -- "Guimaraes" (nom d'usage) ne renvoie chez
  // API-Football que les equipes B/U23/U19/feminine -- l'equipe premiere
  // est enregistree sous "Vitoria SC", sans "Guimaraes" dans son nom
  // officiel du tout. Cle sur "guimaraes" pour couvrir aussi bien
  // "Guimaraes" seul que "Vitoria Guimaraes" (na.includes(key) suffit).
  "guimaraes": "Vitoria SC",
  // Ajoute le 12/09/2026 -- nom officiel API-Football "Academico Viseu"
  // (sans "de"), alors que le nom d'usage courant est "Academico de
  // Viseu" -- le "de" au milieu casse l'inclusion simple des deux cotes.
  "academicodeviseu": "Academico Viseu",
  // Ajoute le 12/09/2026 -- The Odds API (et l'app, si le champ a ete
  // rempli en suivant ce nom) utilise "Jeonbuk Hyundai Motors", mais
  // API-Football connait ce club sous "Jeonbuk Motors" (sans Hyundai) --
  // confirme en direct via getMatchResult (reglement automatique du
  // journal), K League 1, Jeonbuk vs FC Seoul.
  "jeonbukhyundaimotors": "Jeonbuk Motors",
};
// Ajoute le 07/09/2026 -- des mots de liaison ou sigles de forme juridique
// dans le nom d'un club (ex. "RC Celta DE Vigo" chez OddsPapi vs "Celta
// Vigo" tel que saisi) s'intercalent entre les mots significatifs. Comme
// norm() colle tout en une seule chaine sans espaces, "rccetladevigo"
// (mot "de" au milieu) ne matche jamais "celtavigo" via includes(), meme
// si les DEUX noms designent le meme club -- confirme en direct sur
// Getafe vs Celta Vigo (secours OddsPapi en erreur alors que le match
// existait bien). On compare ici mot par mot, apres avoir retire les
// petits mots de liaison et sigles de forme juridique les plus courants
// en Europe -- PAS "ca" pour l'instant (trop ambigu avec les clubs
// argentins "Club Atletico ..." -- a traiter separement si l'app s'etend
// vers l'Amerique du Sud).
const TEAM_NAME_STOPWORDS = new Set(["de", "del", "of", "the", "van", "der", "fc", "cf", "cd", "ac", "rc", "sc", "ud", "a", "la", "el", "los", "las", "sd", "cp"]);
function teamNameTokensMatch(a, b) {
  const wordsA = (a || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .split(/[^a-z0-9]+/).filter(w => w && !TEAM_NAME_STOPWORDS.has(w));
  const wordsB = (b || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .split(/[^a-z0-9]+/).filter(w => w && !TEAM_NAME_STOPWORDS.has(w));
  if (!wordsA.length || !wordsB.length) return false;
  // Ajoute le 12/09/2026 -- certaines sources inversent l'ordre des mots
  // d'un meme club ("Turku PS" vs "TPS Turku" chez The Odds API) -- ni
  // l'inclusion simple ni la comparaison dans l'ordre tape ne matchaient.
  // Trier les mots avant de comparer rend ce test insensible a l'ordre,
  // sans avoir besoin d'un alias par cas rencontre.
  return wordsA.slice().sort().join("") === wordsB.slice().sort().join("");
}
function teamNameMatches(a, b) {
  const na = norm(a), nb = norm(b);
  if (!na || !nb) return false;
  if (na === nb || na.includes(nb) || nb.includes(na)) return true;
  const minLen = Math.min(na.length, nb.length);
  if (minLen >= 5 && na.slice(0, 5) === nb.slice(0, 5)) return true;
  if (teamNameTokensMatch(a, b)) return true;
  for (const key in TEAM_NAME_ALIASES) {
    const aliases = TEAM_NAME_ALIASES[key];
    const naHasKey = na.includes(key), nbHasKey = nb.includes(key);
    const naHasAlias = aliases.some(al => na.includes(al));
    const nbHasAlias = aliases.some(al => nb.includes(al));
    if ((naHasKey && nbHasAlias) || (nbHasKey && naHasAlias)) return true;
  }
  return false;
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

// Ajoute le 06/09/2026 -- OddsPapi renvoie parfois un slug de bookmaker
// avec un suffixe (ex. "pinnacle+30" au lieu de "pinnacle", confirme en
// direct sur Everton vs Manchester United) -- une egalite stricte
// rejetait alors ce book en silence malgre des donnees parfaitement
// valides. On verifie desormais si le slug COMMENCE PAR un nom de
// confiance plutot qu'une correspondance exacte.
function isTrustedOddsPapiBook(bookSlug) {
  return ODDSPAPI_TRUSTED_BOOKS.some(trusted => bookSlug.startsWith(trusted));
}

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

async function fetchOddsPapiFallback(env, homeName, awayName) {
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
  const fixture = oddsPapiFixturePropre(matches);

  const oddsRes = await fetchT(`${base}/odds?apiKey=${env.ODDSPAPI_API_KEY}&fixtureId=${fixture.fixtureId}`);
  if (!oddsRes.ok) {
    const body = await oddsRes.text().catch(() => "");
    throw new Error("OddsPapi odds HTTP " + oddsRes.status + " (fixture " + fixture.statusName + ") — " + body.slice(0, 150));
  }
  const odds = await oddsRes.json();
  if (odds.error) {
    throw new Error("OddsPapi erreur: " + (odds.error.message || JSON.stringify(odds.error)));
  }
  const bookmakerOdds = odds.bookmakerOdds || {};
  const out = { oO25: [], oU25: [], oO15: [], oU15: [], oBTTSyes: [], oBTTSno: [] };
  // Fusion du 07/09/2026 -- totaux (1010/1011 pour 2,5 ; 108/109 pour 1,5)
  // et BTTS (104/105) sont deux marches distincts chez OddsPapi mais la
  // MEME reponse /odds les contient deja tous les deux. Un seul appel
  // fixtures+odds au lieu de deux (un par ancien fallback separe) elimine
  // la collision de rate-limit constatee en prod (Everton vs Man United,
  // Elche vs Real Sociedad : le 2e appel OddsPapi coup sur coup se
  // faisait rejeter par RATE_LIMITED) et divise par deux la consommation
  // de quota quand les deux marches manquent en meme temps.
  const marketMap = { "1010": "oO25", "1011": "oU25", "108": "oO15", "109": "oU15", "104": "oBTTSyes", "105": "oBTTSno" };
  Object.entries(bookmakerOdds).forEach(([bookSlug, bookData]) => {
    if (!isTrustedOddsPapiBook(bookSlug)) return;
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
  const hasAny = out.oO25.length || out.oU25.length || out.oO15.length || out.oU15.length || out.oBTTSyes.length || out.oBTTSno.length;
  return hasAny ? out : null;
}

// Ajoute le 07/09/2026 -- certains championnats (ex. Colombie, Paraguay)
// n'ont AUCUNE entree chez The Odds API, meme approximative : resolveSportKey
// echoue avant meme d'atteindre getOdds(), donc le secours OddsPapi habituel
// (qui ne comble que les trous PARTIELS -- totaux/BTTS manquants -- une fois
// que The Odds API a deja reussi le 1N2) n'est jamais atteint. Ces deux
// fonctions forment un chemin de secours COMPLET, uniquement pour ce cas :
// tout, y compris le 1N2, vient d'OddsPapi. Fonctions volontairement
// separees de fetchOddsPapiFallback/getOdds existantes (jamais modifiees)
// pour ne prendre aucun risque sur les championnats qui fonctionnent deja.
async function fetchOddsPapiFull(env, homeName, awayName) {
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
  const fixture = oddsPapiFixturePropre(matches);

  const oddsRes = await fetchT(`${base}/odds?apiKey=${env.ODDSPAPI_API_KEY}&fixtureId=${fixture.fixtureId}`);
  if (!oddsRes.ok) {
    const body = await oddsRes.text().catch(() => "");
    throw new Error("OddsPapi odds HTTP " + oddsRes.status + " (fixture " + fixture.statusName + ") — " + body.slice(0, 150));
  }
  const odds = await oddsRes.json();
  if (odds.error) {
    throw new Error("OddsPapi erreur: " + (odds.error.message || JSON.stringify(odds.error)));
  }
  const bookmakerOdds = odds.bookmakerOdds || {};
  const out = { o1: [], oX: [], o2: [], oO25: [], oU25: [], oO15: [], oU15: [], oBTTSyes: [], oBTTSno: [] };
  // 101/102/103 = marche "moneyline" (1N2) chez OddsPapi -- confirme via
  // bookmakerOutcomeId explicite ("home"/"draw"/"away") sur un fixture
  // colombien reel le 07/09/2026, en plus des marches deja connus
  // (totaux 1010/1011/108/109, BTTS 104/105).
  const marketMap = { "101": "o1", "102": "oX", "103": "o2", "1010": "oO25", "1011": "oU25", "108": "oO15", "109": "oU15", "104": "oBTTSyes", "105": "oBTTSno" };
  Object.entries(bookmakerOdds).forEach(([bookSlug, bookData]) => {
    if (!isTrustedOddsPapiBook(bookSlug)) return;
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
  const hasAny = Object.values(out).some(arr => arr.length);
  if (!hasAny) throw new Error("OddsPapi : fixture trouve mais aucune cote exploitable");
  return out;
}

async function getOddsFromOddsPapiOnly(env, homeName, awayName) {
  const collect = await fetchOddsPapiFull(env, homeName, awayName);
  // Selection simplifiee (pas de priorite Betclic/Winamax ici -- ces books
  // ne couvrent de toute facon jamais ces championnats, inutile de le
  // verifier a chaque marche) : meilleure cote dispo, avec le meme filtre
  // anti-aberration (mediane x3) que le reste de l'app.
  const out = { spread: {}, bestBook: {} };
  Object.keys(collect).forEach(k => {
    let arr = collect[k];
    if (!arr.length) { out[k] = null; out.bestBook[k] = null; out.spread[k] = null; return; }
    if (arr.length >= 3) {
      const sortedPrices = arr.map(p => p.price).slice().sort((a, b) => a - b);
      const mid = Math.floor(sortedPrices.length / 2);
      const median = sortedPrices.length % 2 ? sortedPrices[mid] : (sortedPrices[mid - 1] + sortedPrices[mid]) / 2;
      const kept = arr.filter(p => p.price <= median * 3 && p.price >= median / 3);
      if (kept.length) arr = kept;
    }
    let best = arr[0], min = arr[0].price, max = arr[0].price;
    arr.forEach(p => {
      if (p.price > best.price) best = p;
      if (p.price < min) min = p.price;
      if (p.price > max) max = p.price;
    });
    out[k] = best.price;
    out.bestBook[k] = best.book;
    out.spread[k] = { spread: max - min, count: arr.length };
  });
  // Repere Pinnacle no-vig calcule depuis les cotes OddsPapi (ajoute le
  // 13/09/2026). Avant, out.pinnacle restait null sur les championnats
  // 100% OddsPapi (ex. Danemark) : la cote Pinnacle apparaissait bien dans
  // "Cotes du marche" mais le repere no-vig manquait dans "Paris coherents".
  const pinPrice = (arr) => {
    if (!arr || !arr.length) return null;
    const p = arr.find(x => /pinnacle/i.test(x.book || ""));
    return p ? p.price : null;
  };
  const noVig2 = (a, b) => { const ia=1/a, ib=1/b, t=ia+ib; return [ia/t, ib/t]; };
  const noVig3 = (a, b, c) => { const ia=1/a, ib=1/b, ic=1/c, t=ia+ib+ic; return [ia/t, ib/t, ic/t]; };
  const pinnacle = { p1: null, pX: null, p2: null, pO25: null, pU25: null };
  const p1r = pinPrice(collect.o1), pXr = pinPrice(collect.oX), p2r = pinPrice(collect.o2);
  if (p1r && pXr && p2r) { const [a,b,c] = noVig3(p1r, pXr, p2r); pinnacle.p1=a; pinnacle.pX=b; pinnacle.p2=c; }
  const pOr = pinPrice(collect.oO25), pUr = pinPrice(collect.oU25);
  if (pOr && pUr) { const [a,b] = noVig2(pOr, pUr); pinnacle.pO25=a; pinnacle.pU25=b; }
  out.pinnacle = (pinnacle.p1!=null || pinnacle.pO25!=null) ? pinnacle : null;
  out.warning = "championnat non couvert par The Odds API -- toutes les cotes proviennent d'OddsPapi (aucune chez Betclic/Winamax/PMU) -- verifie le book avant de jouer";
  return out;
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
    // Fusion du 07/09/2026 -- un seul appel OddsPapi (fixtures+odds) au lieu
  // de deux appels separes (un par ancien fallback), pour eliminer la
  // collision de rate-limit constatee en prod (Everton vs Man United,
  // Elche vs Real Sociedad).
  const totalsMissing = { oO25: !collect.oO25.length, oU25: !collect.oU25.length, oO15: !collect.oO15.length, oU15: !collect.oU15.length };
  const noTotalsAtAll = totalsMissing.oO25 || totalsMissing.oU25 || totalsMissing.oO15 || totalsMissing.oU15;
  const noBttsAtAll = !collect.oBTTSyes.length && !collect.oBTTSno.length;
  if (noTotalsAtAll || noBttsAtAll) {
    const originalIssue = totalsWarning;
    let fallback = null;
    let fallbackErr = null;
    try { fallback = await fetchOddsPapiFallback(env, homeName, awayName); } catch (e) { fallbackErr = e.message; }
    let filledTotals = 0, filledBtts = 0;
    if (fallback) {
      if (noTotalsAtAll) {
        for (const k of ["oO25", "oU25", "oO15", "oU15"]) {
          if (totalsMissing[k] && fallback[k] && fallback[k].length) {
            collect[k] = fallback[k];
            filledTotals += fallback[k].length;
          }
        }
      }
      if (noBttsAtAll && (fallback.oBTTSyes.length || fallback.oBTTSno.length)) {
        collect.oBTTSyes = fallback.oBTTSyes;
        collect.oBTTSno = fallback.oBTTSno;
        filledBtts = fallback.oBTTSyes.length + fallback.oBTTSno.length;
      }
    }
    const parts = [];
    if (originalIssue) parts.push(originalIssue);
    if (noTotalsAtAll) {
      if (filledTotals > 0) {
        parts.push("totaux partiellement absents chez Winamax/Unibet/Betclic \u2014 complet\u00e9s via OddsPapi (secours, " + filledTotals + " cotes trouv\u00e9es)");
      } else {
        const detail = Object.keys(marketsSeenPerBook).length
          ? Object.entries(marketsSeenPerBook).map(([book, mks]) => book + " : " + mks).join(" \u00b7 ")
          : "aucun bookmaker demand\u00e9 n'a r\u00e9pondu pour ce match";
        parts.push("aucune cote 1,5/2,5 manquante re\u00e7ue (secours OddsPapi : " + (fallbackErr ? "erreur \u2014 " + fallbackErr : "ex\u00e9cut\u00e9 sans erreur mais sans donn\u00e9e") + ") \u2014 march\u00e9s re\u00e7us par book (Odds API) : " + detail);
      }
    }
    if (noBttsAtAll) {
      if (filledBtts > 0) {
        parts.push("BTTS absent chez Winamax/Unibet/Betclic -- compl\u00e9t\u00e9 via OddsPapi (secours, " + filledBtts + " cotes trouv\u00e9es)");
      } else if (fallbackErr) {
        parts.push("BTTS : secours OddsPapi en erreur (" + fallbackErr + ")");
      }
    }
    totalsWarning = parts.length ? parts.join(" \u00b7 ") : originalIssue;
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

// Ajoute le 13/09/2026 -- complement a football-data.co.uk (qui ne
// reconnait qu'un nombre limite de pays/divisions) : TheStatsAPI couvre
// 116+ championnats, meme principe que pour le xG et les blessures.
// Reutilise resolveTheStatsAPICompetition deja construit pour le xG.
// Calcule lgH/lgA en moyennant les buts DOMICILE et EXTERIEUR sur tous
// les matchs termines de la saison en cours (pas d'agregat direct
// domicile/exterieur expose par leur endpoint /standings).
async function getLeagueAveragesTSA(env, leagueName, country, season) {
  const cacheKey = "tsa_lgavg:" + norm(leagueName) + ":" + norm(country || "");
  const cached = await cacheGet(env, cacheKey);
  if (cached) return cached;

  const comp = await resolveTheStatsAPICompetition(env, leagueName, country);
  const detail = await theStatsApiGet(env, "/football/competitions/" + comp.id, null);
  const seasonId = detail?.current_season_id;
  if (!seasonId) throw new Error("aucune saison courante trouvée pour ce championnat chez TheStatsAPI");

  let page = 1;
  const homeGoals = [], awayGoals = [];
  for (;;) {
    const res = await theStatsApiGet(env, "/football/matches", {
      competition_id: comp.id, season_id: seasonId, status: "finished", per_page: 100, page,
    });
    const matches = res || [];
    for (const m of matches) {
      if (m.score?.home != null && m.score?.away != null) {
        homeGoals.push(m.score.home);
        awayGoals.push(m.score.away);
      }
    }
    if (matches.length < 100) break;
    page++;
    if (page > 10) break; // filet de securite, jamais attendu en pratique
  }

  if (!homeGoals.length) throw new Error("aucun match terminé trouvé chez TheStatsAPI pour la saison courante");

  const avg = arr => arr.reduce((s, v) => s + v, 0) / arr.length;
  const result = { lgH: avg(homeGoals), lgA: avg(awayGoals), seasonUsed: null };
  await cacheSet(env, cacheKey, result, 604800); // 7 jours, comme les autres agrégats de saison
  return result;
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
