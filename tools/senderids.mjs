/**
 * Värn – Traficomin suojatut tekstiviestien lähettäjätunnukset (SMS Sender ID).
 *
 * Suojattua tunnusta saa käyttää vain sen omistaja: operaattorit eivät välitä viestejä, joissa
 * tunnusta käyttää joku muu. Sovellus käyttää listaa Huijausviestin tarkistuksessa: aito tunnus,
 * tunnusta jäljittelevä lähettäjä ("P0sti") tai brändiä esittävä viesti tavallisesta numerosta.
 *
 * Lähde on Traficomin verkkosivu (HTML-taulukot, ei latausta). Jos sivun rakenne muuttuu niin,
 * ettei tunnuksia löydy, lähde ohitetaan (build ei kaadu) ja edellinen määrä näkyy NOTES.md:ssä.
 *
 * Palauttaa: { ids: [[tunnus, organisaatio], ...], stats }
 */
const PAGE_URL = 'https://traficom.fi/fi/traficomin-myontamat-numerot/suojatut-sms-sender-id-tunnukset';
const MIN_IDS = 50; // alle tämän: sivu on muuttunut tai jäsennys rikki → ohitetaan

const ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', ndash: '–', mdash: '—',
  auml: 'ä', Auml: 'Ä', ouml: 'ö', Ouml: 'Ö', aring: 'å', Aring: 'Å', uuml: 'ü', Uuml: 'Ü', eacute: 'é', Eacute: 'É',
};
export function decodeEntities(s) {
  return String(s)
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&([a-z]+);/gi, (m, n) => ENTITIES[n] ?? ENTITIES[n.toLowerCase()] ?? m);
}
const cellText = (html) => decodeEntities(html.replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();

/** Jäsentää sivun taulukot: rivit, joissa 1. solu = tunnus, 2. = toiminimi, 3. = Y-tunnus. */
export function parseSenderIds(html) {
  const out = new Map();
  let rows = 0;
  for (const tr of String(html).match(/<tr[\s\S]*?<\/tr>/gi) || []) {
    const cells = (tr.match(/<td[\s\S]*?<\/td>/gi) || []).map(cellText);
    if (cells.length < 3) continue; // otsikkorivi (<th>) tai muu
    rows++;
    const [id, org, ytunnus] = cells;
    if (!/^\d{7}-\d$/.test(ytunnus)) continue; // varmistus: kolmas sarake on Y-tunnus
    if (!id || id.length > 20 || !/^[\p{L}\p{N} .&'+\-_]+$/u.test(id)) continue;
    if (!org || org.length > 120) continue;
    const key = id.toLowerCase();
    if (!out.has(key)) out.set(key, [id, org]);
  }
  return {ids: [...out.values()].sort((a, b) => a[0].localeCompare(b[0], 'fi')), rows};
}

export async function loadSenderIds() {
  const res = await fetch(PAGE_URL, {headers: {'User-Agent': 'varn-threatdata (github.com/K750074/varn-threatdata)'}});
  if (!res.ok) throw new Error(`${PAGE_URL} → HTTP ${res.status}`);
  const {ids, rows} = parseSenderIds(await res.text());
  if (ids.length < MIN_IDS) throw new Error(`liian vähän tunnuksia (${ids.length}/${rows} riviä) – sivu muuttunut?`);
  return {ids, stats: {ids: ids.length, rows}};
}
