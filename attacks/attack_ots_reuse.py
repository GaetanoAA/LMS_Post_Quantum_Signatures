"""
DEMO 1 — Falsificazione per riuso della chiave one-time (state rollback).

Scenario: il firmatario usa una chiave LMS stateful. Lo stato (indice q) viene
riportato indietro — ripristino di un backup, snapshot di una VM, chiave
clonata su più server. Risultato: più messaggi diversi firmati con la STESSA
chiave LM-OTS (stesso q).

Attacco: per ogni catena i l'attaccante conosce il nodo al passo
min_k a_i^(k) (il minimo tra le firme raccolte). Può quindi "andare avanti"
lungo la catena fino a qualunque passo >= di quel minimo. Cerca un
randomizzatore C tale che tutte le cifre (checksum incluso) del digest del
messaggio scelto siano >= dei minimi: a quel punto costruisce una firma
valida senza conoscere alcun segreto.

Esecuzione:  python -m attacks.attack_ots_reuse [--firme K] [--max-tentativi N]
"""
import argparse
import os
import shutil
import tempfile
import time

from lms import LMS_BY_H, LMOTS_BY_W, StatefulSigner
from lms.lmots import chain, digits, message_digest
from lms.params import u32str

TARGET = "Bonifico urgente di 1.000.000 EUR sul conto di Mallory".encode()


def collect_signatures(k: int):
    """Simula k ripristini dello stato: k firme diverse tutte con q = 0."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "chiave.json")
    signer = StatefulSigner.create(path, LMS_BY_H[5].typecode, LMOTS_BY_W[8].typecode)
    shutil.copy(path, path + ".backup")            # backup "innocente" dello stato
    msgs, sigs = [], []
    for j in range(k):
        shutil.copy(path + ".backup", path)        # ripristino: q torna a 0
        m = f"Documento legittimo n. {j}".encode()
        msgs.append(m)
        sigs.append(StatefulSigner(path).sign(m))
    pk = signer.public_key()
    shutil.rmtree(d)
    return pk, msgs, sigs


def parse(sig: bytes, P):
    q = int.from_bytes(sig[:4], "big")
    C = sig[8:8 + P.n]
    y = [sig[8 + P.n * (i + 1): 8 + P.n * (i + 2)] for i in range(P.p)]
    tail = sig[8 + P.n * (P.p + 1):]               # typecode LMS + percorso
    return q, C, y, tail


def forge(pk, msgs, sigs, max_tries: int):
    P = pk.ots
    parsed = [parse(s, P) for s in sigs]
    q = parsed[0][0]
    assert all(p[0] == q for p in parsed), "le firme non condividono q"
    # cifre firmate da ciascuna firma (il verificatore pubblico le ricalcola)
    signed_digits = [digits(message_digest(pk.I, q, C, m), P)
                     for m, (_, C, _, _) in zip(msgs, parsed)]
    # per ogni catena: firma che rivela il nodo più "basso"
    best = []
    for i in range(P.p):
        k = min(range(len(sigs)), key=lambda j: signed_digits[j][i])
        best.append((signed_digits[k][i], parsed[k][2][i]))

    t0 = time.time()
    for tries in range(1, max_tries + 1):
        C = os.urandom(P.n)                         # C lo sceglie l'attaccante!
        a = digits(message_digest(pk.I, q, C, TARGET), P)
        if all(a[i] >= best[i][0] for i in range(P.p)):
            y = [chain(pk.I, q, i, best[i][0], a[i], best[i][1]) for i in range(P.p)]
            ots_sig = u32str(P.typecode) + C + b"".join(y)
            forged = u32str(q) + ots_sig + parsed[0][3]   # stesso percorso di Merkle
            return forged, tries, time.time() - t0
    return None, max_tries, time.time() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--firme", type=int, default=4, help="firme raccolte con lo stesso q")
    ap.add_argument("--max-tentativi", type=int, default=2_000_000)
    args = ap.parse_args()

    print(f"[1] Il firmatario ripristina lo stato {args.firme} volte e firma {args.firme} "
          "documenti diversi con q = 0 (LMS H5, LM-OTS W8)")
    pk, msgs, sigs = collect_signatures(args.firme)
    for m, s in zip(msgs, sigs):
        print(f"    firma valida su {m.decode()!r}: {pk.verify(m, s)}")

    print(f"[2] L'attaccante cerca C per il messaggio: {TARGET.decode()!r}")
    forged, tries, dt = forge(pk, msgs, sigs, args.max_tentativi)
    if forged is None:
        print(f"    nessuna falsificazione in {tries} tentativi ({dt:.1f}s): "
              "con poche firme serve più calcolo, riprova con --firme maggiore")
        return
    print(f"    trovato C dopo {tries} tentativi ({dt:.2f}s)")
    print(f"[3] Verifica con la chiave pubblica LMS legittima: {pk.verify(TARGET, forged)}")
    print("    => FIRMA FALSIFICATA ACCETTATA. Mai riusare una chiave one-time!")


if __name__ == "__main__":
    main()
