/**
 * Värn – DNS-estolistan kokoaminen. Vain juridisesti sallivat lähteet (kaupallinen käyttö ok):
 *   - StevenBlack hosts (MIT): mainokset ja seuranta (~75 000)
 *   - URLhaus (CC0, abuse.ch): haittaohjelmapalvelimet
 *   - Oma Suomi-typosquat (generoitu itse, ei lisenssiä): kalastelu suomalaisilta brändeiltä
 *
 * Tuottaa yhden lajitellun, duplikaatittoman verkkotunnuslistan.
 */

const SOURCES = {
  stevenblack: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  urlhaus: "https://urlhaus.abuse.ch/downloads/hostfile/",
};

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** Suomalaiset brändit, joita huijarit jäljittelevät. Näistä generoidaan typosquat-muunnelmat. */
const FI_BRANDS = [
  "posti", "op", "nordea", "spankki", "s-pankki", "danskebank", "danske", "handelsbanken",
  "aktia", "saastopankki", "spop", "omasp", "poppankki",
  "kela", "vero", "omakanta", "kanta", "traficom", "poliisi", "suomi", "suomifi", "dvv",
  "telia", "elisa", "dna", "verkkokauppa", "tokmanni", "prisma", "kesko", "kruoka",
  "lahitapiola", "pohjola", "fennia", "mandatum", "osuuspankki",
];

/** Yleiset pääteosat, joilla huijaussivut esiintyvät. */
const FI_TLDS = ["com", "net", "info", "fi", "org", "online", "site", "xyz"];

async function fetchLines(url, authKey) {
  const headers = {"User-Agent": "Varn-ThreatData/1"};
  if (authKey) headers["Auth-Key"] = authKey;
  const res = await fetch(url, {headers});
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  const text = await res.text();
  return text.split("\n");
}

/** Poimii verkkotunnuksen hosts-rivistä ("0.0.0.0 domain" tai "127.0.0.1 domain") tai pelkästä nimestä. */
function extractDomain(line) {
  const s = line.trim();
  if (!s || s.startsWith("#")) return null;
  const parts = s.split(/\s+/);
  let domain = parts.length >= 2 ? parts[1] : parts[0];
  domain = domain.toLowerCase().replace(/\.$/, "");
  if (domain === "localhost" || domain === "0.0.0.0" || domain === "::1") return null;
  return DOMAIN_RE.test(domain) ? domain : null;
}

async function loadHostsSource(url, authKey) {
  const out = new Set();
  let rejected = 0;
  for (const line of await fetchLines(url, authKey)) {
    const d = extractDomain(line);
    if (d) out.add(d);
    else if (line.trim() && !line.trim().startsWith("#")) rejected++;
  }
  return {domains: out, rejected};
}

/**
 * Generoi typosquat-muunnelmat suomalaisista brändeistä. Esim. "posti" ->
 * p0sti, posti-fi, postii, pösti jne. yhdistettynä pääteosiin.
 */
export function generateFinnishTyposquat() {
  const out = new Set();
  const leet = {o: "0", i: "1", l: "1", a: "4", e: "3", s: "5"};

  for (const brand of FI_BRANDS) {
    const variants = new Set();
    // 1. kirjainten korvaus (leet)
    for (let i = 0; i < brand.length; i++) {
      const c = brand[i];
      if (leet[c]) variants.add(brand.slice(0, i) + leet[c] + brand.slice(i + 1));
    }
    // 2. kirjaimen kahdennus
    for (let i = 0; i < brand.length; i++) {
      variants.add(brand.slice(0, i + 1) + brand[i] + brand.slice(i + 1));
    }
    // 3. viereiset vaihdot (näppäimistövirheet)
    for (let i = 0; i < brand.length - 1; i++) {
      variants.add(brand.slice(0, i) + brand[i + 1] + brand[i] + brand.slice(i + 2));
    }
    // 4. yhdistelmät: pääte + huijausten teemasanat (Kyberturvallisuuskeskuksen ja pankkien
    //    varoitusten mukaan huijarit käyttävät näitä: tunnistautuminen, vahvistus, maksun palautus,
    //    tietoturvapäivitys, tilin vahvistus, tietojen päivitys).
    const themes = [
      "fi", "-fi", "suomi", "-suomi", "-turvallisuus", "-tunnistautuminen", "-tunnistus",
      "-vahvistus", "-vahvista", "-maksu", "-maksupalautus", "-palautus", "-paivitys",
      "-tili", "-verkkopankki", "-pankki", "-asiointi", "-kirjautuminen", "-login", "-secure",
    ];
    for (const theme of themes) variants.add(brand + theme);

    // Yhdistä pääteosiin
    for (const v of variants) {
      if (v === brand) continue; // ei estetä oikeaa brändiä tässä (ne ovat eri domaineja)
      if (v.length < 4) continue; // liian lyhyt muunnos aiheuttaisi vääriä estoja (esim. 0p.com)
      for (const tld of FI_TLDS) {
        const domain = `${v}.${tld}`;
        if (DOMAIN_RE.test(domain)) out.add(domain);
      }
    }
  }
  return out;
}

/**
 * Tunnettujen DoH-palvelimien verkkotunnukset. Estämällä nämä selaimet, jotka käyttävät omaa
 * salattua DNS:ää, putoavat takaisin järjestelmän DNS:ään (Värnin suodattimeen).
 * EI sisällä Värnin omia palvelimia (cloudflare-dns.com, dns.google), jotka toimivat tunnelin ohi.
 */
export function dohBypassDomains() {
  return [
    // Chromen ja Firefoxin DoH-päätepisteet
    "chrome.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "firefox.dns.nextdns.io",
    // Yleiset DoH-palvelut, joita sovellukset voivat käyttää suodattimen ohi
    "doh.opendns.com",
    "dns.adguard.com", "dns-family.adguard.com", "dns-unfiltered.adguard.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
    "doh.dns.sb", "dns.sb",
    "doh.libredns.gr",
    "dns.adguard-dns.com",
    "freedns.controld.com",
    "doh.mullvad.net", "dns.mullvad.net",
    "dns10.quad9.net", "dns11.quad9.net", "dns9.quad9.net",
    "doh-fi.blahdns.com", "doh-de.blahdns.com",
    "ordns.he.net",
  ];
}

export async function buildBlocklist(options = {}) {
  const all = new Set();
  const stats = {};

  // StevenBlack (MIT)
  try {
    const sb = await loadHostsSource(SOURCES.stevenblack);
    sb.domains.forEach((d) => all.add(d));
    stats.stevenblack = sb.domains.size;
  } catch (e) {
    stats.stevenblack = `virhe: ${e.message}`;
  }

  // URLhaus (CC0). Fair use: haetaan kerran vuorokaudessa.
  try {
    const uh = await loadHostsSource(SOURCES.urlhaus, options.urlhausAuthKey);
    uh.domains.forEach((d) => all.add(d));
    stats.urlhaus = uh.domains.size;
  } catch (e) {
    stats.urlhaus = `ohitettu: ${e.message}`;
  }

  // Oma Suomi-typosquat (ei lisenssiä)
  const fi = generateFinnishTyposquat();
  fi.forEach((d) => all.add(d));
  stats.finnishTyposquat = fi.size;

  // DoH-kiertosuoja: estä selainten oma salattu DNS, jotta ne palaavat Värnin suodattimeen
  const doh = dohBypassDomains();
  doh.forEach((d) => all.add(d));
  stats.dohBypass = doh.length;

  return {domains: [...all].sort(), stats};
}
