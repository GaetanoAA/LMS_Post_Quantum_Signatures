"""
DEMO 2 — Perché LM-OTS ha bisogno del checksum.

Senza checksum, UNA sola firma basta per falsificare: chi conosce il nodo
al passo a_i della catena i può calcolare tutti i passi successivi. Quindi
qualsiasi digest Q' con cifre a'_i >= a_i per ogni i è firmabile.

Con il checksum le cifre aggiuntive Cksm = sum(2^w - 1 - a_i) DIMINUISCONO
quando le a_i aumentano: alzare una cifra del digest obbliga ad abbassare il
checksum, cosa impossibile senza conoscere i segreti. Da una sola firma la
falsificazione richiede di rompere la funzione hash
(trovare preimmagini o seconde preimmagini), non solo più calcolo.

Parte A — parametri ridotti (digest troncato a 3 byte, w = 8) per mostrare
          l'attacco in pochi secondi, con e senza checksum.
Parte B — parametri reali (n = 32, w = 8): stima del costo mediano senza
          checksum (media su 2000 firme casuali).

Esecuzione:  python -m attacks.attack_no_checksum
"""
import math
import os

from lms import LMOTS_BY_W
from lms.lmots import H, chain, coef

W = 8
MAXD = (1 << W) - 1
TOY_BYTES = 3                       # digest "giocattolo": 3 cifre da 8 bit
I, q = os.urandom(16), 0
TARGET = b"Mallory e' l'amministratore"


def toy_digits(Q: bytes, with_checksum: bool) -> list[int]:
    a = [coef(Q, i, W) for i in range(TOY_BYTES)]
    if with_checksum:
        ck = sum(MAXD - d for d in a)            # al massimo 3*255 = 765 -> 2 cifre
        a += [ck >> 8, ck & 0xFF]
    return a


def toy_Q(C: bytes, msg: bytes) -> bytes:
    return H(I + C + msg)[:TOY_BYTES]


def toy_attack(with_checksum: bool, max_tries: int = 300_000):
    n_chains = TOY_BYTES + (2 if with_checksum else 0)
    x = [os.urandom(32) for _ in range(n_chains)]                     # segreti
    pub = [chain(I, q, i, 0, MAXD, x[i]) for i in range(n_chains)]     # cime catene

    # il firmatario firma un messaggio legittimo
    C = os.urandom(32)
    a = toy_digits(toy_Q(C, b"messaggio legittimo"), with_checksum)
    y = [chain(I, q, i, 0, a[i], x[i]) for i in range(n_chains)]

    # l'attaccante cerca C' per il suo messaggio con cifre >= a
    for tries in range(1, max_tries + 1):
        C2 = os.urandom(32)
        b = toy_digits(toy_Q(C2, TARGET), with_checksum)
        if all(b[i] >= a[i] for i in range(n_chains)):
            y2 = [chain(I, q, i, a[i], b[i], y[i]) for i in range(n_chains)]
            ok = all(chain(I, q, i, b[i], MAXD, y2[i]) == pub[i] for i in range(n_chains))
            return tries, ok
    return None, False


def real_params_cost():
    """Senza checksum, con n=32 e w=8, le 32 cifre di Q sono uniformi e
    indipendenti: P[successo] = prod_i (256 - a_i) / 256 per la firma data."""
    P = LMOTS_BY_W[8]
    samples = []
    for _ in range(2000):
        Q = os.urandom(32)
        a = [coef(Q, i, 8) for i in range(32)]
        samples.append(-sum(math.log2((256 - d) / 256) for d in a))
    samples.sort()
    return P, samples[len(samples) // 2]


def main():
    print("PARTE A — parametri ridotti (3 cifre da 8 bit)")
    tries, ok = toy_attack(with_checksum=False)
    print(f"  SENZA checksum: falsificazione trovata dopo {tries} tentativi, valida = {ok}")
    tries, ok = toy_attack(with_checksum=True)
    if tries is None:
        print("  CON checksum:   nessuna falsificazione in 300.000 tentativi")
    else:
        print(f"  CON checksum:   trovato dopo {tries} tentativi (solo se Q' ha le stesse cifre di Q)")
    print("  Motivo: se a'_i >= a_i per ogni i, allora Cksm' <= Cksm; servirebbe anche\n"
          "  Cksm' >= Cksm, quindi a' = a: si può 'rifirmare' solo lo stesso digest.")

    print("\nPARTE B — parametri reali LMOTS_SHA256_N32_W8, senza checksum")
    _, bits = real_params_cost()
    print(f"  costo mediano stimato: circa 2^{bits:.0f} hash SHA-256 per falsificare")
    print("  -> fattibile per un attaccante con GPU/ASIC (sicurezza nominale: 2^128).")
    print("  Con il checksum, da una sola firma non si falsifica senza rompere SHA-256.")


if __name__ == "__main__":
    main()
