# varn-threatdata

Värn-sovelluksen uhkatiedot: allekirjoitettu datapaketti, joka päivittyy automaattisesti joka yö.

Sovellus lataa paketin ja tekee kaiken vertailun puhelimessa. Jokainen käyttäjä lataa saman tiedoston, joten lataus ei paljasta mitään käyttäjän puhelimesta. (GitHub näkee latauksen IP-osoitteen – mainitse tämä tietosuojaselosteessa.)

## Rakenne

1. **build** – hakee lähteet (ulkoinen `yaml`-riippuvuus). **Ei näe allekirjoitusavainta.**
2. **sign-and-publish** – ei npm installia, vain Noden omat moduulit. Tarkistaa paketin sisällön itsenäisesti ja allekirjoittaa vasta sitten. Avain on `signing`-ympäristössä, joka sallii vain `main`-haaran.

## Turvamekanismit

- ECDSA P-256 -allekirjoitus, pää- ja vara-avain (vara-avaimen yksityinen osa vain offline)
- SHA-256-tiiviste, ei taaksepäin -sääntö, sovellus varoittaa yli 14 vrk vanhoista tiedoista
- Järkevyystarkistus (pudotus > 30 % tai < 50 pakettia pysäyttää julkaisun)
- `never-flag`-lista, joka tarkistetaan molemmissa vaiheissa
- Etäsäädöt vain tarkoille paketinnimille, enintään 50, eivät voi koskaan sallia tunnettua stalkerwarea
- Actions lukittu commit-tunnisteisiin, `npm ci --ignore-scripts`, oletusoikeudet nolla

## Etäsäädöt

`data/rule-overrides.json` → `allowlistPackages`: tarkka paketinnimi asialliselle sovellukselle, joka aiheuttaa vääriä hälytyksiä.

## Lähteet ja lisenssit

Katso `data/sources.json`. Echapin data on CC BY 4.0 -lisensoitu: lähdemaininta näytetään sovelluksessa.
