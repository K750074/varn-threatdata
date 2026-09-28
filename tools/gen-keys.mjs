/**
 * Värn – allekirjoitusavainten luonti (ECDSA P-256).
 *
 *   node tools/gen-keys.mjs          → private-key.pem         (pääavain → GitHubin "signing"-ympäristöön)
 *   node tools/gen-keys.mjs backup   → backup-private-key.pem  (VARA-avain → vain salasanamanageriin, EI GitHubiin)
 *
 * Molempien julkiset avaimet upotetaan sovellukseen. Jos pääavain joskus vuotaa,
 * siirrytään vara-avaimeen ilman, että vanhat sovellusversiot lakkaavat päivittymästä.
 *
 * Miksi P-256 eikä Ed25519: Android tukee ECDSA P-256 -tarkistusta natiivisti kaikissa versioissa.
 */
import {generateKeyPairSync} from 'node:crypto';
import {writeFileSync, existsSync} from 'node:fs';

const isBackup = process.argv[2] === 'backup';
const file = isBackup ? 'backup-private-key.pem' : 'private-key.pem';

if (existsSync(file)) {
  console.error(`${file} on jo olemassa. Poista se ensin, jos haluat varmasti uuden avaimen.`);
  process.exit(1);
}

const {publicKey, privateKey} = generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
  publicKeyEncoding: {type: 'spki', format: 'der'},
  privateKeyEncoding: {type: 'pkcs8', format: 'pem'},
});
writeFileSync(file, privateKey, {mode: 0o600});

console.log(`Yksityinen avain tallennettu: ${file}`);
console.log(isBackup
  ? 'Tallenna se salasanamanageriin ja poista levyltä. ÄLÄ lisää GitHubiin.'
  : 'Lisää sisältö GitHubin "signing"-ympäristön secretiksi SIGNING_KEY_PEM.');
console.log(`\nJulkinen avain Kotliniin (${isBackup ? 'BACKUP_PUBLIC_KEY_B64' : 'PRIMARY_PUBLIC_KEY_B64'}):\n`);
console.log(publicKey.toString('base64'));
