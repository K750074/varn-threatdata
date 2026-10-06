/**
 * Värn – uhkatietopaketin kokoaminen (vaihe 1/2).
 *
 * Tämä vaihe EI näe allekirjoitusavainta. Se hakee lähteet ulkoisilla
 * riippuvuuksilla (yaml), joten avain pidetään tarkoituksella erillään.
 * Allekirjoitus tehdään erillisessä vaiheessa: tools/sign-bundle.mjs.
 *
 * Tuottaa kansioon out/:
 *   bundle.json.gz   – varsinainen data
 *   manifest.json    – versio, tiiviste, määrät (allekirjoitetaan vaiheessa 2)
 *   NOTES.md         – julkaisun kuvaus
 *
 * Ympäristömuuttujat:
 *   ABUSECH_AUTH_KEY       (valinnainen) MalwareBazaar-avain
 *   PREVIOUS_MANIFEST_URL  (valinnainen) edellinen julkaisu järkevyystarkistusta varten
 */
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {mkdir, writeFile, readFile} from 'node:fs/promises';
import YAML from 'yaml';
import {loadExodusTrackers} from './exodus.mjs';
import {buildBlocklist, HOME_COUNTRY} from './blocklist.mjs';

const OUT = 'out';
const SCHEMA = 1;
const MAX_DROP = 0.3; // jos määrä putoaa yli 30 %, julkaisu pysähtyy
const MIN_STALKERWARE_PACKAGES = 50; // absoluuttinen alaraja

const ECHAP_URL =
  'https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml';

const PACKAGE_RE = /^[A-Za-z][\w]*(\.[\w]+)+$/;
const HEX_RE = /^[0-9a-f]+$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

const log = (...a) => console.log('•', ...a);

async function fetchText(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return res.text();
}

const normalizeHex = (s) => String(s).replace(/[^0-9a-fA-F]/g, '').toLowerCase();

// ------------------------------------------------------------------
// Lähteet
// ------------------------------------------------------------------

async function loadEchap() {
  const entries = YAML.parse(await fetchText(ECHAP_URL));
  if (!Array.isArray(entries)) throw new Error('Echap: odottamaton rakenne');

  const packages = new Set();
  const certs = new Set();
  const names = {};
  let rejected = 0;

  for (const e of entries) {
    for (const raw of e.packages || []) {
      const p = String(raw).trim();
      if (PACKAGE_RE.test(p)) {
        packages.add(p);
        names[p] = String(e.name || '').slice(0, 80);
      } else rejected++;
    }
    for (const raw of e.certificates || []) {
      const c = normalizeHex(raw);
      // SHA-1 (40) tai SHA-256 (64)
      if (HEX_RE.test(c) && (c.length === 40 || c.length === 64)) certs.add(c);
      else rejected++;
    }
  }
  log(`Echap: ${entries.length} tuotetta, ${packages.size} pakettia, ${certs.size} varmennetta, hylätty ${rejected}`);
  return {packages, certs, names};
}

async function loadMalwareBazaar() {
  const key = process.env.ABUSECH_AUTH_KEY;
  if (!key) {
    log('MalwareBazaar: ohitettu (ei ABUSECH_AUTH_KEY)');
    return {hashes: new Set(), skipped: true};
  }
  const body = new URLSearchParams({query: 'get_file_type', file_type: 'apk', limit: '1000'});
  const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
    method: 'POST',
    headers: {'Auth-Key': key},
    body,
  });
  if (!res.ok) throw new Error(`MalwareBazaar → HTTP ${res.status}`);
  const json = await res.json();
  if (json.query_status !== 'ok') throw new Error(`MalwareBazaar: ${json.query_status}`);
  const hashes = new Set(
    (json.data || []).map((d) => normalizeHex(d.sha256_hash)).filter((h) => SHA256_RE.test(h)),
  );
  log(`MalwareBazaar: ${hashes.size} APK-tiivistettä`);
  return {hashes, skipped: false};
}

// ------------------------------------------------------------------
// Tarkistukset
// ------------------------------------------------------------------

async function loadPreviousManifest() {
  const url = process.env.PREVIOUS_MANIFEST_URL;
  if (!url) return null;
  try {
    return JSON.parse(await fetchText(url));
  } catch (e) {
    log(`Edellistä manifestia ei saatu (${e.message}) – oletetaan ensimmäinen julkaisu`);
    return null;
  }
}

function sanityCheck(counts, prev) {
  if (counts.stalkerwarePackages < MIN_STALKERWARE_PACKAGES) {
    throw new Error(`Liian vähän stalkerware-paketteja (${counts.stalkerwarePackages}) – lähde rikki?`);
  }
  if (!prev?.counts) return;
  for (const [k, now] of Object.entries(counts)) {
    const before = prev.counts[k];
    if (before > 0 && now < before * (1 - MAX_DROP)) {
      throw new Error(`${k} putosi ${before} → ${now} (yli ${MAX_DROP * 100} %). Julkaisu pysäytetty.`);
    }
  }
}

function versionNow(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return Number(`${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}`);
}

// ------------------------------------------------------------------
// Pääohjelma
// ------------------------------------------------------------------

async function main() {
  const neverFlag = new Set(JSON.parse(await readFile('data/never-flag.json', 'utf8')).packages);
  const rawOverrides = JSON.parse(await readFile('data/rule-overrides.json', 'utf8'));
  const allowlistPackages = (rawOverrides.allowlistPackages || []).map((s) => String(s).trim());
  const invalid = allowlistPackages.filter((p) => !PACKAGE_RE.test(p));
  if (invalid.length) throw new Error(`rule-overrides: virheelliset paketinnimet: ${invalid.join(', ')}`);
  const overrides = {allowlistPackages};
  const sources = JSON.parse(await readFile('data/sources.json', 'utf8'));

  const [echap, mb, exodus, blocklist, prev] = await Promise.all([
    loadEchap(),
    loadMalwareBazaar(),
    loadExodusTrackers().catch((e) => {
      log(`Exodus: ohitettu (${e.message})`);
      return null;
    }),
    buildBlocklist({urlhausAuthKey: process.env.URLHAUS_AUTH_KEY}).catch((e) => {
      log(`Estolista: ohitettu (${e.message})`);
      return null;
    }),
    loadPreviousManifest(),
  ]);

  // Suoja virheellistä lähdedataa vastaan
  for (const p of neverFlag) {
    if (echap.packages.delete(p)) {
      delete echap.names[p];
      log(`VAROITUS: ${p} oli lähteessä, mutta on never-flag-listalla – poistettu`);
    }
  }

  const sortSet = (s) => [...s].sort();
  const version = versionNow();
  const createdAt = new Date().toISOString();

  // Estolista: universaali osa (mainokset, seuranta, haittaohjelmat, DoH-kierto) + maakohtaiset
  // typosquat-listat. Kenttä "blocklist" = universaali + kotimaan (fi) typosquat, jotta vanhakin
  // sovellus suojaa koti­markkinan. Kenttä "typosquat" = kaikki maat, josta sovellus lataa käyttäjän
  // alueen mukaan (universaali + oma alue). Päällekkäisyys poistetaan natiivissa (Set).
  const universal = blocklist ? blocklist.universal : [];
  const typosquat = blocklist ? blocklist.typosquat : {};
  const homeScams = typosquat[HOME_COUNTRY] || [];
  const composedBlocklist = [...new Set([...universal, ...homeScams])].sort();

  const bundle = {
    schema: SCHEMA,
    version,
    createdAt,
    stalkerware: {
      packages: sortSet(echap.packages),
      certs: sortSet(echap.certs),
      names: echap.names,
    },
    malwareApkSha256: sortSet(mb.hashes),
    trackers: (exodus || []).sort((a, b) => a.name.localeCompare(b.name)),
    blocklist: composedBlocklist,
    typosquat,
    ruleOverrides: overrides,
    sources: sources
      .filter((s) => !(s.optional && s.id === 'malwarebazaar-apk' && mb.skipped))
      .map(({id, name, url, license, attribution}) => ({id, name, url, license, attribution})),
  };

  const typosquatTotal = Object.values(typosquat).reduce((n, a) => n + (Array.isArray(a) ? a.length : 0), 0);
  const counts = {
    stalkerwarePackages: bundle.stalkerware.packages.length,
    stalkerwareCerts: bundle.stalkerware.certs.length,
    malwareApkSha256: bundle.malwareApkSha256.length,
    trackers: bundle.trackers.length,
    blocklist: bundle.blocklist.length,
    typosquat: typosquatTotal,
  };
  if (mb.skipped) delete counts.malwareApkSha256; // ei verrata, jos lähde ohitettiin tarkoituksella
  sanityCheck(counts, prev);

  if (prev?.version && version <= prev.version) {
    throw new Error(`Versio ${version} ei ole uudempi kuin edellinen ${prev.version}`);
  }

  const gz = gzipSync(Buffer.from(JSON.stringify(bundle)), {level: 9});
  const manifest = {
    schema: SCHEMA,
    version,
    createdAt,
    bundleFile: 'bundle.json.gz',
    bundleSha256: createHash('sha256').update(gz).digest('hex'),
    bundleSize: gz.length,
    counts,
  };
  const manifestBytes = Buffer.from(JSON.stringify(manifest, null, 2) + '\n');

  await mkdir(OUT, {recursive: true});
  await writeFile(`${OUT}/bundle.json.gz`, gz);
  await writeFile(`${OUT}/manifest.json`, manifestBytes);
  await writeFile(
    `${OUT}/NOTES.md`,
    [
      `Värn-uhkatiedot, versio ${version}`,
      '',
      ...Object.entries(counts).map(([k, v]) => `- ${k}: ${v}${prev?.counts?.[k] != null ? ` (edellinen ${prev.counts[k]})` : ''}`),
      '',
      'Lähteet:',
      ...bundle.sources.map((s) => `- ${s.attribution} – ${s.url}`),
    ].join('\n'),
  );

  if (blocklist) log(`Estolista: ${JSON.stringify(blocklist.stats)}`);
  log(`Koottu: versio ${version}, paketti ${(gz.length / 1024).toFixed(1)} kt (allekirjoittamaton)`);
}

main().catch((e) => {
  console.error('✗', e.message);
  process.exit(1);
});
