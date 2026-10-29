/**
 * Värn – valtiotason vakoiluohjelmien verkkotunnukset (IOC).
 *
 * Lähde: MVT-projektin indeksi (mvt-project/mvt-indicators, indicators.yaml), josta otetaan VAIN
 * kokoelmat, jotka on julkaistu kaupallisen käytön sallivalla lisenssillä:
 *   - AmnestyTech/investigations  (CC BY 2.0 – lähdemaininta näytetään sovelluksessa)
 *   - mvt-project/mvt-indicators  (MIT)
 * Muiden tahojen repot (esim. Citizen Lab, CC BY-NC-SA) ohitetaan, samoin kokoelmat, joiden ainoa
 * lähde on Citizen Lab. Stalkerware (Echap) tulee jo omana lähteenään.
 *
 * Palauttaa: { campaigns: [{name, source}], domains: [[domain, campaignIndex]], stats }
 */
import YAML from 'yaml';

const INDEX_URL = 'https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml';
const ALLOWED_OWNERS = {
  AmnestyTech: 'Amnesty International (CC BY 2.0)',
  'mvt-project': 'MVT indicators (MIT)',
};
const NON_COMMERCIAL_ONLY = new Set(['Citizen Lab']);
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const PATTERN_RE = /^\[domain-name:value\s*=\s*'([^']+)'\]$/;
const MAX_DOMAINS = 50000; // järkevyysraja: indeksi rikki tai väärä tiedosto

async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return res.text();
}

const shortName = (n) => String(n || '').replace(/\s*Indicators of Compromise\s*$/i, '').trim().slice(0, 80);

export async function loadSpywareDomains() {
  const index = YAML.parse(await fetchText(INDEX_URL));
  const entries = Array.isArray(index?.indicators) ? index.indicators : [];
  const campaigns = [];
  const owner = new Map(); // domain → kampanjaindeksi (ensimmäinen voittaa)
  const stats = {collections: 0, skipped: 0, domains: 0};

  for (const e of entries) {
    const gh = e?.github;
    const sources = Array.isArray(e?.sources) ? e.sources : [];
    if (e?.type !== 'github' || !gh || !ALLOWED_OWNERS[gh.owner]) { stats.skipped++; continue; }
    if (sources.length > 0 && sources.every((s) => NON_COMMERCIAL_ONLY.has(s))) { stats.skipped++; continue; }
    if (!/\.stix2$/.test(String(gh.path || ''))) { stats.skipped++; continue; }

    const url = `https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/${gh.branch}/${gh.path}`;
    let stix;
    try {
      stix = JSON.parse(await fetchText(url));
    } catch (err) {
      console.log(`• Vakoiluohjelmat: ${gh.path} ohitettu (${err.message})`);
      stats.skipped++;
      continue;
    }
    const idx = campaigns.length;
    let n = 0;
    for (const o of stix?.objects || []) {
      if (o?.type !== 'indicator') continue;
      const m = PATTERN_RE.exec(String(o.pattern || '').trim());
      if (!m) continue;
      const d = m[1].trim().toLowerCase().replace(/\.$/, '');
      if (!DOMAIN_RE.test(d) || owner.has(d)) continue;
      owner.set(d, idx);
      n++;
    }
    if (n === 0) continue; // ei verkkotunnuksia (esim. pelkät tiivisteet) → ei kampanjaa listalle
    campaigns.push({name: shortName(e.name), source: ALLOWED_OWNERS[gh.owner]});
    stats.collections++;
  }

  if (owner.size > MAX_DOMAINS) throw new Error(`Vakoiluohjelmat: epäilyttävän paljon verkkotunnuksia (${owner.size})`);
  const domains = [...owner.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  stats.domains = domains.length;
  return {campaigns, domains, stats};
}
