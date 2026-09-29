/**
 * Värn – Exodus Privacy -seurantatunnisteiden haku.
 *
 * Lähde: https://reports.exodus-privacy.eu.org/api/trackers (Exodus Privacy)
 * Muunnetaan Värnin muotoon: { name, category, prefixes: [code_signature-osat] }.
 *
 * Lisenssi: Exodus-ohjelmisto on AGPL v3; tunnistedata on Exodus Privacyn omien ehtojen alaista.
 * Sovelluksessa näytetään lähdemaininta (ks. data/sources.json).
 */
const URL = "https://reports.exodus-privacy.eu.org/api/trackers";
const CODE_SIG_RE = /^[a-zA-Z][\w]*(\.[\w]+)+$/;
const MIN_TRACKERS = 200; // järkevyysraja: jos vähemmän, lähde on todennäköisesti rikki

export async function loadExodusTrackers() {
  const res = await fetch(URL, {headers: {"User-Agent": "Varn-ThreatData/1"}});
  if (!res.ok) throw new Error(`Exodus API → HTTP ${res.status}`);
  const json = await res.json();
  const raw = json && json.trackers ? json.trackers : {};
  const out = [];
  for (const id of Object.keys(raw)) {
    const t = raw[id];
    if (!t || typeof t.name !== "string") continue;
    const sig = String(t.code_signature || "").trim();
    // code_signature voi olla useampi paketti pystyviivalla eroteltuna, tai regex-tyylinen.
    // Otetaan vain selkeät Java-pakettimuodot, jotta vältetään väärät osumat.
    const prefixes = sig
      .split("|")
      .map((s) => s.replace(/\\/g, "").replace(/\.$/, "").trim())
      .filter((s) => CODE_SIG_RE.test(s));
    if (prefixes.length === 0) continue;
    const category = Array.isArray(t.categories) && t.categories.length ? String(t.categories[0]) : "Other";
    out.push({name: t.name.slice(0, 60), category, prefixes});
  }
  if (out.length < MIN_TRACKERS) throw new Error(`Exodus: liian vähän tunnisteita (${out.length}) – lähde rikki?`);
  return out;
}
