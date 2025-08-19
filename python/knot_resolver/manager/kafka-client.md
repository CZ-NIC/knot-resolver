# Kafka klient

Veškerá logika je obsažena v `kafka_client.py` modulu.
Ke komunikace se používá `kafka-python` implementace.

## Design komunikace

Klient zprávy ze serveru (Kafka broker) konzumuje (KafkaConsumer) a žádné neposílá. Obsahem zpráv jsou vždy data souboru.

### Struktura zpráv

**key**: název souboru  
**value**: obsah souboru nebo jeho část  
**headers**:
- `hostname`: str ; hostname resolveru pro který je zpráva určena
- `files-name`: str ; název souboru
- `total-chunks`: int ; na kolik částí je soubor rozdělen
- `chunk-index`: int ; o kterou část souboru se jedná


### Konfiugrační soubory

Mají koncovku `.json`, `.yaml` nebo `.yml`.
Po úspěšném zpracování nastane reload celé konfigurace (delayed 5s). Novou konfiguraci je potřeba poslat jako poslední zprávu po úspěšném zaslání všech dalších zpráv (nových souborů), jinak může aplikace konfigurace selhat na v ten moment ještě neexitující soubor, který se stále nezpracoval nebo neodeslal. 

### Ostatní soubory (e.g. .rpz)

Ostatní soubory, které nemají koncovku konfigurace.
Po jejich úspěšném zpracování nastane renew konfigurace (delayed 5s). Všechny tyto souboru je potřeba zaslat před samotnou novou konfigurací.

## Postup zpracování zpráv
1. Resolver přijme zprávu od Kafka brokeru
1. Porovná se `headers.hostname` s hostname resolveru  
   Pokud se hostname shodují, zpracování pokračuje, v opačním případě se zpráva zahodí (není určena pro tento resolver).
1. Pokud zpráva obsahuje kompletní data souboru, je možné rovnou přejít k ukládání souboru.
    - Pokud se jedná pouze o část souboru, každá tato část se uloží do adresáře s koncovkou .chunks a jménem podle `headers.chunk-index`.
    - Pokud jsou k dispozici všechny části souboru podle `headers.total-chunks`, je možné je poskládat do jednoho souboru podle správného pořadí. Vznikde tak dočasný soubor s koncovkou .tmp.
1. Uložení nových dat do souboru:
    - Pokud se jedná o soubor s konfigurací, dojde k jeho validaci.
    - Pokud původní soubor již existuje, vytvoří se jeho záloha s koncovkou .backup.
    - Nová data souboru jsou uložena do dočasného souboru s koncovkou .tmp.
    - Dočasný soubor s novými daty nahrazuje původní soubor.
1. Pokud se jedná o soubor s konfigurací (.json, .yaml nebo .yml) zavolá se kompletní reload konfigurace, tzn. veškerá konfigurace se načte od nuly ze souborů včetně nové uložené konfigurace. V opačném případě se zavolá pouze renew konfigurace, tzn nenastala změna v konfiguraci, ale v některém ze souborů, např .rpz.

Chyba při zpracování jedné zprávy neovlivňuje zpracování ostatních, může ale chybět jedna část většího souboru a tak nedojde k sestavení kompletního souboru.

Pokud selže reload nebo renew konfigurace, resolver stále poběží se starou validní konfigurací.

## Kafka konfigurace

Nastavení kafky má vlastní sekci v konfiguraci **kafka:** `datamodel/kafka_schema.py`.

```yaml
# /etc/knot-resolver/config.yaml

kafka:
  enable: true          # default: false
  topic: knot-resolver  # default

  # server (broker) nebo seznam serverů (brokerů)
  server: kafka-jezek-test01.nic.cz  # default: localhost@9092

  # Adresář, kam se budou ukládat soubory a konfigurace získaná pomocí kafky.
  files-dir: /var/lib/knot-resolver  # default

  # protokol a certifikaty
  security-protocol: ssl  # default: plaintext
  key-file: /path/to/client.key
  cert-file: /path/to/client.crt
  ca-file: /path/to/cacert.crt
```

V současnosti není možné konfiguravat všechny možnosti pro KafkaConsumer, ale jen to co vyžadoval Ježek.
Není problém co koliv přidat.
