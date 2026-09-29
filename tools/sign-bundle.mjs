/**
 * Värn – uhkatietopaketin tarkistus ja allekirjoitus (vaihe 2/2).
 *
 * TURVAPERIAATE: tämä skripti käyttää VAIN Noden sisäänrakennettuja moduuleja.
 * Allekirjoitusvaiheessa ei ajeta npm installia, joten mikään ulkoinen paketti
 * ei pääse käsiksi avaimeen.
 *
 * Ennen allekirjoitusta paketin sisältö tarkistetaan itsenäisesti. Jos kokoamisvaihe
 * olisi saastunut, tämä pysäyttää vääristellyn paketin eikä allekirjoita sitä.
 *
 * Ympäristömuuttujat:
 *   SIGNING_KEY_PEM   yksityinen avain PEM-muodossa (GitHubissa "signing"-ympäristön secret)
 *   SIGNING_KEY_FILE  vaihtoehtoisesti polku PEM-tiedostoon (paikallinen testaus)
 */
import {createHash, createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {readFile, writeFile} from 'node:fs/promises';

const OUT = 'out';
const PACKAGE_RE = /^[A-Za-z][\w]*(\.[\w]+)+$/;
const CERT_RE = /^([0-9a-f]{40}|[0-9a-f]{64})$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const ALLOWED_KEYS = new Set([
  'schema', 'version', 'createdAt', 'stalkerware', 'malwareApkSha256', 'trackers', 'ruleOverrides', 'sources',
]);
const MIN_PACKAGES = 50;
const MAX_OVERRIDES = 50;
const MAX_AGE_MS = 6 * 60 * 60 * 1000; // paketin oltava tuore (kooste samalta ajolta)

function fail(msg) {
  throw new Error(`Tarkistus hylkäsi paketin: ${msg}`);
}

async function main() {
  let pem = process.env.SIGNING_KEY_PEM;
  if (!pem && process.env.SIGNING_KEY_FILE) pem = await readFile(process.env.SIGNING_KEY_FILE, 'utf8');
  if (!pem) throw new Error('SIGNING_KEY_PEM puuttuu.');
  const privateKey = createPrivateKey(pem);

  const manifestBytes = await readFile(`${OUT}/manifest.json`);
  const gz = await readFile(`${OUT}/bundle.json.gz`);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));

  // --- Manifesti ---
  if (manifest.schema !== 1) fail('tuntematon skeema');
  if (!Number.isInteger(manifest.version) || String(manifest.version).length !== 10) fail('versio');
  const age = Date.now() - Date.parse(manifest.createdAt);
  if (!(age > -5 * 60 * 1000 && age < MAX_AGE_MS)) fail(`createdAt ei ole tuore (${manifest.createdAt})`);
  if (manifest.bundleFile !== 'bundle.json.gz') fail('bundleFile');
  if (gz.length !== manifest.bundleSize) fail('koko ei täsmää');
  if (createHash('sha256').update(gz).digest('hex') !== manifest.bundleSha256) fail('tiiviste ei täsmää');

  // --- Paketin sisältö ---
  const bundle = JSON.parse(gunzipSync(gz).toString('utf8'));
  for (const k of Object.keys(bundle)) if (!ALLOWED_KEYS.has(k)) fail(`tuntematon kenttä ${k}`);
  if (bundle.schema !== 1 || bundle.version !== manifest.version) fail('versio/skeema ei täsmää manifestiin');

  const pkgs = bundle.stalkerware?.packages || [];
  const certs = bundle.stalkerware?.certs || [];
  const hashes = bundle.malwareApkSha256 || [];
  if (pkgs.length < MIN_PACKAGES) fail(`liian vähän paketteja (${pkgs.length})`);
  if (!pkgs.every((p) => PACKAGE_RE.test(p))) fail('virheellinen paketinnimi');
  if (!certs.every((c) => CERT_RE.test(c))) fail('virheellinen varmenne');
  if (!hashes.every((h) => SHA256_RE.test(h))) fail('virheellinen APK-tiiviste');

  const c = manifest.counts || {};
  if (c.stalkerwarePackages !== pkgs.length || c.stalkerwareCerts !== certs.length) fail('määrät eivät täsmää');

  const neverFlag = JSON.parse(await readFile('data/never-flag.json', 'utf8')).packages;
  const hit = neverFlag.filter((p) => pkgs.includes(p));
  if (hit.length) fail(`never-flag-paketteja mukana: ${hit.join(', ')}`);

  const trackers = bundle.trackers || [];
  if (!Array.isArray(trackers)) fail('trackers ei ole taulukko');
  for (const tr of trackers) {
    if (!tr || typeof tr.name !== 'string' || !Array.isArray(tr.prefixes)) fail('virheellinen tracker');
  }
  if (c.trackers !== trackers.length) fail('tracker-määrä ei täsmää');

  const ov = bundle.ruleOverrides || {};
  for (const k of Object.keys(ov)) if (k !== 'allowlistPackages') fail(`tuntematon etäsäätö ${k}`);
  const allow = ov.allowlistPackages || [];
  if (allow.length > MAX_OVERRIDES) fail('liikaa etäsäätöjä');
  if (!allow.every((p) => PACKAGE_RE.test(p))) fail('virheellinen etäsäätö');
  // Etäsäätö ei saa koskaan sallia tunnettua stalkerwarea
  const clash = allow.filter((p) => pkgs.includes(p));
  if (clash.length) fail(`etäsäätö sallisi tunnetun stalkerwaren: ${clash.join(', ')}`);

  // --- Allekirjoitus ---
  const signature = sign('sha256', manifestBytes, privateKey); // DER → Javan SHA256withECDSA
  if (!verify('sha256', manifestBytes, createPublicKey(privateKey), signature)) {
    throw new Error('Allekirjoituksen itsetarkistus epäonnistui');
  }
  await writeFile(`${OUT}/manifest.sig`, signature.toString('base64') + '\n');
  console.log(`• Tarkistettu ja allekirjoitettu: versio ${manifest.version} (${pkgs.length} pakettia, ${certs.length} varmennetta)`);
}

main().catch((e) => {
  console.error('✗', e.message);
  process.exit(1);
});
