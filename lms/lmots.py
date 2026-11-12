"""
LM-OTS: firma one-time di Leighton-Micali (RFC 8554, sezione 4).

Idea: per ogni cifra a_i (in base 2^w) del digest del messaggio si percorre
una catena di hash partendo dal segreto x[i]. La firma rivela il nodo dopo
a_i passi; il verificatore completa la catena fino a 2^w - 1 passi e ottiene
la chiave pubblica. Il checksum impedisce di "andare avanti" sulle catene.

ATTENZIONE: ogni chiave LM-OTS va usata UNA SOLA VOLTA (vedi attacks/).
"""
import hashlib
import os

from .params import (
    LMOTS, LmotsParams, D_PBLC, D_MESG,
    u32str, u16str, u8str, strTou32,
)


class InvalidSignature(Exception):
    """Firma malformata (lunghezza o typecode errati)."""


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- Cifre di Winternitz e checksum (RFC 8554, sez. 3.1.3 e 4.4) -------------
def coef(S: bytes, i: int, w: int) -> int:
    """i-esima cifra di w bit della stringa S (bit più significativi prima)."""
    digits_per_byte = 8 // w
    byte = S[(i * w) // 8]
    shift = 8 - (w * (i % digits_per_byte) + w)
    return (byte >> shift) & ((1 << w) - 1)


def checksum(Q: bytes, params: LmotsParams, use_checksum: bool = True) -> int:
    """Cksm(Q) = somma di (2^w - 1 - a_i) sulle cifre del digest, shiftata di ls."""
    if not use_checksum:
        return 0
    total = 0
    for i in range(params.n * 8 // params.w):
        total += params.max_digit - coef(Q, i, params.w)
    return (total << params.ls) & 0xFFFF


def digits(Q: bytes, params: LmotsParams, use_checksum: bool = True) -> list[int]:
    """Le p cifre a_0..a_{p-1} di Q || Cksm(Q): una per ogni catena."""
    S = Q + u16str(checksum(Q, params, use_checksum))
    n_digits = params.p if use_checksum else params.n * 8 // params.w
    return [coef(S, i, params.w) for i in range(n_digits)]


def chain(I: bytes, q: int, i: int, start: int, end: int, tmp: bytes) -> bytes:
    """Applica la funzione di catena dal passo `start` (incluso) a `end` (escluso).

    Ogni passo è  tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp):
    l'indice j rende ogni anello della catena una funzione diversa.
    """
    prefix = I + u32str(q) + u16str(i)
    for j in range(start, end):
        tmp = H(prefix + u8str(j) + tmp)
    return tmp


def message_digest(I: bytes, q: int, C: bytes, message: bytes) -> bytes:
    """Q = H(I || u32str(q) || u16str(D_MESG) || C || message)."""
    return H(I + u32str(q) + u16str(D_MESG) + C + message)


# --- Chiave privata --------------------------------------------------------
class LmotsPrivateKey:
    def __init__(self, params: LmotsParams, I: bytes, q: int, x: list[bytes]):
        assert len(I) == 16 and len(x) == params.p
        self.params, self.I, self.q, self.x = params, I, q, x
        self.used = False

    @classmethod
    def from_seed(cls, params: LmotsParams, I: bytes, q: int, seed: bytes):
        """Derivazione pseudo-casuale dei segreti (RFC 8554, Appendice A):
        x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)."""
        x = [H(I + u32str(q) + u16str(i) + u8str(0xFF) + seed) for i in range(params.p)]
        return cls(params, I, q, x)

    @classmethod
    def generate(cls, params: LmotsParams, I: bytes | None = None, q: int = 0):
        I = I or os.urandom(16)
        x = [os.urandom(params.n) for _ in range(params.p)]
        return cls(params, I, q, x)

    def public_key(self) -> "LmotsPublicKey":
        P = self.params
        y = [chain(self.I, self.q, i, 0, P.max_digit, self.x[i]) for i in range(P.p)]
        K = H(self.I + u32str(self.q) + u16str(D_PBLC) + b"".join(y))
        return LmotsPublicKey(P, self.I, self.q, K)

    def sign(self, message: bytes, C: bytes | None = None,
             use_checksum: bool = True, allow_reuse: bool = False) -> bytes:
        """Firma LM-OTS: u32str(type) || C || y[0] || ... || y[p-1].

        C (randomizzatore) normalmente è casuale; si può passare per i test.
        `use_checksum=False` e `allow_reuse=True` servono SOLO alle demo d'attacco.
        """
        if self.used and not allow_reuse:
            raise RuntimeError("Chiave LM-OTS già usata: il riuso rompe la sicurezza!")
        self.used = True
        P = self.params
        C = C if C is not None else os.urandom(P.n)
        Q = message_digest(self.I, self.q, C, message)
        a = digits(Q, P, use_checksum)
        y = [chain(self.I, self.q, i, 0, a[i], self.x[i]) for i in range(len(a))]
        return u32str(P.typecode) + C + b"".join(y)


# --- Chiave pubblica e verifica --------------------------------------------
class LmotsPublicKey:
    def __init__(self, params: LmotsParams, I: bytes, q: int, K: bytes):
        self.params, self.I, self.q, self.K = params, I, q, K

    def serialize(self) -> bytes:
        return u32str(self.params.typecode) + self.I + u32str(self.q) + self.K

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            Kc = candidate_public_key(self.params.typecode, self.I, self.q,
                                      message, signature)
        except InvalidSignature:
            return False
        return Kc == self.K


def candidate_public_key(pubtype: int, I: bytes, q: int, message: bytes,
                         signature: bytes, use_checksum: bool = True) -> bytes:
    """Algoritmo 4b dell'RFC: ricalcola la chiave pubblica candidata Kc.

    Si completano le catene: da y[i] (passo a_i) fino al passo 2^w - 1.
    """
    if len(signature) < 4:
        raise InvalidSignature("firma troppo corta")
    sigtype = strTou32(signature[:4])
    if sigtype != pubtype or sigtype not in LMOTS:
        raise InvalidSignature("typecode LM-OTS non corrispondente")
    P = LMOTS[sigtype]
    n_chains = P.p if use_checksum else P.n * 8 // P.w
    if len(signature) != 4 + P.n * (n_chains + 1):
        raise InvalidSignature("lunghezza firma LM-OTS errata")
    C = signature[4:4 + P.n]
    y = [signature[4 + P.n * (i + 1): 4 + P.n * (i + 2)] for i in range(n_chains)]
    Q = message_digest(I, q, C, message)
    a = digits(Q, P, use_checksum)
    z = [chain(I, q, i, a[i], P.max_digit, y[i]) for i in range(n_chains)]
    return H(I + u32str(q) + u16str(D_PBLC) + b"".join(z))
