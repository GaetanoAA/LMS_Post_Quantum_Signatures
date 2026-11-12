"""
Benchmark dei parametri di LMS: dimensioni (esatte, da formula) e tempi
(misurati sulla nostra implementazione Python).

Esecuzione:  python -m bench.benchmark   (circa 1-2 minuti)
Output:      bench/results.json e grafici PNG in bench/charts/
"""
import gc
import json
import os
import statistics
import time

from lms import LMS_BY_H, LMOTS_BY_W, LmsPrivateKey

OUT = os.path.dirname(__file__)
WS = (1, 2, 4, 8)
HS = (5, 10, 15, 20, 25)

# Dimensioni di riferimento (byte) di altri schemi, dagli standard:
# Ed25519 (RFC 8032), ML-DSA-44 (FIPS 204), SLH-DSA-SHA2-128s/f (FIPS 205)
OTHERS = {
    "Ed25519 (non PQ)": {"pk": 32, "sig": 64},
    "ML-DSA-44": {"pk": 1312, "sig": 2420},
    "SLH-DSA-128s": {"pk": 32, "sig": 7856},
    "SLH-DSA-128f": {"pk": 32, "sig": 17088},
}


def sizes():
    return {f"w{w}_h{h}": LMS_BY_H[h].sig_len(LMOTS_BY_W[w]) for w in WS for h in HS}


def hash_counts(w: int, h: int) -> dict:
    """Numero di invocazioni di SHA-256 (analitico)."""
    P = LMOTS_BY_W[w]
    per_leaf = P.p * (1 + P.max_digit) + 1 + 1   # segreti + catene + K + foglia
    keygen = (1 << h) * per_leaf + (1 << h) - 1   # + nodi interni
    verify_avg = 1 + P.p * P.max_digit / 2 + 1 + 1 + h  # Q + catene + K + foglia + percorso
    return {"keygen": keygen, "verify_avg": verify_avg}


def time_it(fn, repeat: int) -> float:
    ts = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - t0)
    return statistics.median(ts)


def measure():
    gc.disable()
    res = {}
    for h in (5, 10):
        for w in WS:
            t0 = time.perf_counter()
            sk = LmsPrivateKey.generate(LMS_BY_H[h], LMOTS_BY_W[w])
            keygen = time.perf_counter() - t0
            pk = sk.public_key()
            msg = b"benchmark"
            sigs = []

            def do_sign():
                sigs.append(sk.sign(msg))
            sign = time_it(do_sign, 31)
            # verifica: mediana su firme diverse (il costo dipende dalle cifre)
            vt = []
            for s in sigs:
                t0 = time.perf_counter()
                assert pk.verify(msg, s)
                vt.append(time.perf_counter() - t0)
            verify = statistics.median(vt)
            res[f"w{w}_h{h}"] = {"keygen_s": keygen, "sign_ms": sign * 1e3,
                                 "verify_ms": verify * 1e3}
            print(f"h={h:2d} w={w}: keygen {keygen:7.2f}s  "
                  f"firma {sign*1e3:7.2f}ms  verifica {verify*1e3:7.2f}ms")
    return res


def main():
    data = {"sizes": sizes(), "timings": measure(), "others": OTHERS,
            "hash_counts": {f"w{w}_h{h}": hash_counts(w, h) for w in WS for h in HS}}
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(data, f, indent=1)
    from bench.charts import make_charts
    make_charts(data, os.path.join(OUT, "charts"))
    print("Grafici salvati in bench/charts/")


if __name__ == "__main__":
    main()
