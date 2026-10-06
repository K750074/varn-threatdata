/**
 * Värn – DNS-estolistan kokoaminen. Vain juridisesti sallivat lähteet (kaupallinen käyttö ok):
 *   - StevenBlack hosts (MIT): mainokset ja seuranta (~75 000)   [universaali]
 *   - URLhaus (CC0, abuse.ch): haittaohjelmapalvelimet            [universaali]
 *   - DoH-kiertosuoja (oma kuratointi)                           [universaali]
 *   - Oma typosquat (generoitu itse, ei lisenssiä): kalastelu paikallisilta brändeiltä [maakohtainen]
 *
 * Aluetietoinen: typosquat generoidaan maakohtaisesti (COUNTRIES). Kansainvälistyminen on vain
 * uuden maan lisäys COUNTRIES-rakenteeseen – moottori ja sovelluksen logiikka pysyvät samoina.
 *
 * Palauttaa: { universal: [...], typosquat: { fi:[...], se:[...] }, stats }
 */

const SOURCES = {
  stevenblack: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
  urlhaus: "https://urlhaus.abuse.ch/downloads/hostfile/",
};

const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Yleiset pääteosat, joilla huijaussivut esiintyvät (jaetaan kaikille maille maan oman ccTLD:n lisäksi).
const GENERIC_TLDS = ["com", "net", "info", "org", "online", "site", "xyz"];

/**
 * Maakohtaiset brändit, teemasanat ja pääteosat. Lisää uusi maa tähän – ei muuta tarvita.
 * Teemasanat ja brändit ASCII-muodossa (verkkotunnukset ovat ASCII/punycode; huijarit käyttävät
 * ASCII-muunnelmia, esim. "sakerhet" eikä "säkerhet").
 */
export const COUNTRIES = {
  fi: {
    label: "Suomi",
    brands: [
      "posti", "op", "nordea", "spankki", "s-pankki", "danskebank", "danske", "handelsbanken",
      "aktia", "saastopankki", "spop", "omasp", "poppankki",
      "kela", "vero", "omakanta", "kanta", "traficom", "poliisi", "suomi", "suomifi", "dvv",
      "telia", "elisa", "dna", "verkkokauppa", "tokmanni", "prisma", "kesko", "kruoka",
      "lahitapiola", "pohjola", "fennia", "mandatum", "osuuspankki",
    ],
    themes: [
      "fi", "-fi", "suomi", "-suomi", "-turvallisuus", "-tunnistautuminen", "-tunnistus",
      "-vahvistus", "-vahvista", "-maksu", "-maksupalautus", "-palautus", "-paivitys",
      "-tili", "-verkkopankki", "-pankki", "-asiointi", "-kirjautuminen", "-login", "-secure",
    ],
    tlds: ["fi", ...GENERIC_TLDS],
  },
  // Ruotsi: aloituslista, jota laajennetaan ennen Ruotsin-julkaisua. Rakenne on todistettu
  // kahdella maalla, joten lisäys on pelkkää dataa.
  se: {
    label: "Ruotsi",
    brands: [
      "swedbank", "seb", "handelsbanken", "nordea", "lansforsakringar", "icabanken", "ica",
      "skandia", "avanza", "nordnet", "klarna", "bankid", "swish",
      "skatteverket", "forsakringskassan", "csn", "1177", "postnord",
      "telia", "tele2", "comviq", "telenor",
    ],
    themes: [
      "se", "-se", "sverige", "-sverige", "-sakerhet", "-verifiera", "-verifiering",
      "-bekrafta", "-betalning", "-aterbetalning", "-uppdatering", "-konto", "-inloggning",
      "-logga-in", "-login", "-secure", "-bankid", "-swish",
    ],
    tlds: ["se", ...GENERIC_TLDS],
  },
};

/** Värnin kotimarkkina: aina mukana estolistassa (myös ulkomailla olevan suomalaisen suojaksi). */
export const HOME_COUNTRY = "fi";

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
 * Geneerinen typosquat-generaattori: brändeistä muunnelmat (leet-korvaus, kirjaimen kahdennus,
 * näppäinvaihto, teemasanat) yhdistettynä pääteosiin. Kieliriippumaton moottori.
 */
export function generateTyposquat(brands, themes, tlds) {
  const out = new Set();
  const leet = {o: "0", i: "1", l: "1", a: "4", e: "3", s: "5"};
  const brandList = Array.isArray(brands) ? brands : [];
  const themeList = Array.isArray(themes) ? themes : [];
  const tldList = Array.isArray(tlds) ? tlds : GENERIC_TLDS;

  for (const brand of brandList) {
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
    // 4. pääte + huijausten teemasanat
    for (const theme of themeList) variants.add(brand + theme);

    for (const v of variants) {
      if (v === brand) continue; // oikeaa brändiä ei estetä (eri domain)
      if (v.length < 4) continue; // liian lyhyt muunnos aiheuttaisi vääriä estoja (esim. 0p.com)
      for (const tld of tldList) {
        const domain = `${v}.${tld}`;
        if (DOMAIN_RE.test(domain)) out.add(domain);
      }
    }
  }
  return out;
}

/** Yhden maan typosquat-lista. */
export function generateCountryTyposquat(code) {
  const c = COUNTRIES[code];
  if (!c) return new Set();
  return generateTyposquat(c.brands, c.themes, c.tlds);
}

/** Säilytetään vanhan nimen vuoksi (= Suomi). */
export function generateFinnishTyposquat() {
  return generateCountryTyposquat("fi");
}

/**
 * Tunnettujen DoH-palvelimien verkkotunnukset. Estämällä nämä selaimet, jotka käyttävät omaa
 * salattua DNS:ää, putoavat takaisin järjestelmän DNS:ään (Värnin suodattimeen).
 * EI sisällä Värnin omia palvelimia (cloudflare-dns.com, dns.google), jotka toimivat tunnelin ohi.
 */
export function dohBypassDomains() {
  return [
    "chrome.cloudflare-dns.com", "mozilla.cloudflare-dns.com", "firefox.dns.nextdns.io",
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

/**
 * Kokoaa estolistan. Universaali osa (mainokset, seuranta, haittaohjelmat, DoH-kierto) on sama
 * kaikkialla; typosquat on maakohtainen. Palauttaa universaalin listan ja maakohtaiset listat
 * erikseen, jotta sovellus voi ladata käyttäjän alueen mukaan.
 */
export async function buildBlocklist(options = {}) {
  const universal = new Set();
  const stats = {};

  // StevenBlack (MIT) – universaali
  try {
    const sb = await loadHostsSource(SOURCES.stevenblack);
    sb.domains.forEach((d) => universal.add(d));
    stats.stevenblack = sb.domains.size;
  } catch (e) {
    stats.stevenblack = `virhe: ${e.message}`;
  }

  // URLhaus (CC0) – universaali
  try {
    const uh = await loadHostsSource(SOURCES.urlhaus, options.urlhausAuthKey);
    uh.domains.forEach((d) => universal.add(d));
    stats.urlhaus = uh.domains.size;
  } catch (e) {
    stats.urlhaus = `ohitettu: ${e.message}`;
  }

  // DoH-kiertosuoja – universaali
  const doh = dohBypassDomains();
  doh.forEach((d) => universal.add(d));
  stats.dohBypass = doh.length;

  // Maakohtainen typosquat
  const typosquat = {};
  const tstats = {};
  for (const code of Object.keys(COUNTRIES)) {
    const set = generateCountryTyposquat(code);
    typosquat[code] = [...set].sort();
    tstats[code] = set.size;
  }
  stats.typosquat = tstats;

  return {universal: [...universal].sort(), typosquat, stats};
}
