# LMS: firme post-quantum basate su hash (RFC 8554)

Progetto per l'esame di Crittografia, Laurea Magistrale in Sicurezza Informatica (LM-66),
Università degli Studi di Milano. Autore: Gaetano Angelo Alberto Loizzo.

Implementazione in Python puro (solo `hashlib`, nessuna libreria crittografica esterna) dello schema di firma
Leighton-Micali (LM-OTS + LMS) come specificato nell'RFC 8554. Il repository
contiene anche due demo d'attacco e un benchmark dei parametri.

## Struttura

```
lms/                 nucleo dell'implementazione (~560 righe)
  params.py          typecode, costanti di dominio, codifiche u32str/u16str
  lmots.py           firma one-time di Winternitz: catene, checksum, firma, verifica
  lms.py             albero di Merkle, percorso di autenticazione, verifica
  hss.py             verifica HSS (serve solo per i vettori di test ufficiali)
  state.py           chiave su file con aggiornamento atomico del contatore
tests/               12 test (vettori RFC 8554 Appendice F + test funzionali)
attacks/             demo d'attacco
bench/               benchmark, risultati (results.json) e grafici PNG
presentazione/       slide d'esame (PDF)
```

Requisiti: Python 3.10 o successivo. Per i grafici del benchmark serve `matplotlib`.

## Come eseguire

Tutti i comandi vanno lanciati dalla cartella principale del progetto.

```bash
python -m unittest discover -s tests -t . -v   # 12 test, ~3 s
python -m attacks.attack_ots_reuse             # demo 1: riuso della chiave OTS
python -m attacks.attack_no_checksum           # demo 2: perché serve il checksum
python -m bench.benchmark                      # ~1-2 minuti, rigenera grafici
```

Esempio d'uso della libreria:

```python
from lms import LMS_BY_H, LMOTS_BY_W, LmsPrivateKey, StatefulSigner

sk = LmsPrivateKey.generate(LMS_BY_H[10], LMOTS_BY_W[4])   # 1024 firme
pk = sk.public_key()
sig = sk.sign(b"messaggio")
assert pk.verify(b"messaggio", sig)

# Con lo stato salvato su disco (reserve-then-sign)
signer = StatefulSigner.create("chiave.json", lms_type=6, ots_type=3)
sig = signer.sign(b"firmware v1.2")
```

## Validazione

I vettori di test dell'Appendice F dell'RFC 8554 sono in `tests/rfc8554_vectors.json`.

- **Test Case 1**: verifica di una firma HSS a due livelli (H5/W8 + H5/W8).
- **Test Case 2**: l'RFC fornisce SEED e I della chiave privata. Le chiavi vengono
  rigenerate e la firma (3.860 byte) viene riprodotta **byte per byte**, usando lo stesso
  randomizzatore C.
- Le firme con un bit alterato, troncate, con `q` modificato o su un messaggio diverso
  vengono rifiutate.

## Demo d'attacco

**1. Riuso della chiave one-time** (`attacks/attack_ots_reuse.py`). Lo stato viene
ripristinato da un backup più volte, quindi lo stesso `q` firma messaggi diversi.
L'attaccante tiene, per ogni catena, il nodo più basso rivelato; poi cerca un `C` per cui
tutte le cifre del proprio messaggio (checksum incluso) superano quei minimi, completa le
catene e riusa il percorso di Merkle. Con 4 firme riusate la falsificazione si trova in
meno di un secondo e la chiave pubblica legittima la accetta.

**2. Assenza del checksum** (`attacks/attack_no_checksum.py`). Con parametri ridotti,
senza checksum, una sola firma basta per falsificare in pochi tentativi; con il checksum
non ci sono successi. Per i parametri reali (n = 32, w = 8) il costo stimato senza checksum
è di circa 2^45 hash.

## Risultati principali (h = 10)

| w | firma LMS | firma (ms) | verifica (ms) | generazione chiavi (s) |
|---|-----------|-----------|---------------|------------------------|
| 1 | 8.844 B   | 0,7       | 0,4           | 0,8                    |
| 2 | 4.620 B   | 0,5       | 0,4           | 0,7                    |
| 4 | 2.508 B   | 0,6       | 0,6           | 1,1                    |
| 8 | 1.452 B   | 4,0       | 4,0           | 8,7                    |

I tempi sono misurati in Python puro e dipendono dalla macchina: conta l'andamento,
non il valore assoluto.

## Limiti noti

- HSS è implementato solo lato verifica.
- L'albero viene tenuto tutto in memoria: per h ≥ 20 servirebbero algoritmi di
  attraversamento (es. BDS) o HSS.
- Non sono incluse le varianti SHA-256/192 e SHAKE256 introdotte da NIST SP 800-208.
- Il codice è didattico: non è a tempo costante e non va usato in produzione.

## Riferimenti

- RFC 8554, *Leighton-Micali Hash-Based Signatures* (2019)
- NIST SP 800-208, *Recommendation for Stateful Hash-Based Signature Schemes* (2020)
- RFC 8391, *XMSS: eXtended Merkle Signature Scheme* (2018)
- FIPS 204 (ML-DSA) e FIPS 205 (SLH-DSA), 2024
