"""
LMS: albero di Merkle sopra 2^h chiavi LM-OTS (RFC 8554, sezione 5).

- Le foglie sono gli hash delle chiavi pubbliche LM-OTS.
- La chiave pubblica LMS è la radice T[1] (più I e i typecode).
- La firma contiene: q, la firma LM-OTS con la q-esima chiave e il
  percorso di autenticazione (h nodi fratelli) dalla foglia alla radice.

Numerazione dei nodi: radice = 1, figli di r = 2r e 2r+1,
foglia della chiave q = 2^h + q.
"""
import os

from .params import (
    LMS, LMOTS, LmsParams, LmotsParams, D_LEAF, D_INTR,
    u32str, u16str, strTou32,
)
from .lmots import H, LmotsPrivateKey, candidate_public_key, InvalidSignature


class KeyExhausted(Exception):
    """Tutte le 2^h chiavi one-time sono state usate."""


def leaf_hash(I: bytes, r: int, ots_K: bytes) -> bytes:
    return H(I + u32str(r) + u16str(D_LEAF) + ots_K)


def node_hash(I: bytes, r: int, left: bytes, right: bytes) -> bytes:
    return H(I + u32str(r) + u16str(D_INTR) + left + right)


class LmsPrivateKey:
    """Chiave privata LMS con albero completo in memoria.

    I segreti LM-OTS sono derivati da SEED (Appendice A dell'RFC), quindi
    la chiave privata "vera" è solo (I, SEED, q). L'albero è una cache.
    """

    def __init__(self, lms: LmsParams, ots: LmotsParams, I: bytes, seed: bytes,
                 q: int = 0, tree: list[bytes] | None = None):
        assert len(I) == 16 and len(seed) == lms.m
        self.lms, self.ots, self.I, self.seed, self.q = lms, ots, I, seed, q
        self.tree = tree if tree is not None else self._build_tree()

    @classmethod
    def generate(cls, lms: LmsParams, ots: LmotsParams):
        return cls(lms, ots, os.urandom(16), os.urandom(lms.m))

    # -- costruzione dell'albero -------------------------------------------
    def ots_key(self, q: int) -> LmotsPrivateKey:
        return LmotsPrivateKey.from_seed(self.ots, self.I, q, self.seed)

    def _build_tree(self) -> list[bytes]:
        n_leaves = 1 << self.lms.h
        T = [b""] * (2 * n_leaves)
        for q in range(n_leaves):
            K = self.ots_key(q).public_key().K
            T[n_leaves + q] = leaf_hash(self.I, n_leaves + q, K)
        for r in range(n_leaves - 1, 0, -1):
            T[r] = node_hash(self.I, r, T[2 * r], T[2 * r + 1])
        return T

    # -- chiave pubblica ----------------------------------------------------
    def public_key(self) -> "LmsPublicKey":
        return LmsPublicKey(self.lms, self.ots, self.I, self.tree[1])

    @property
    def remaining(self) -> int:
        return (1 << self.lms.h) - self.q

    # -- firma --------------------------------------------------------------
    def auth_path(self, q: int) -> list[bytes]:
        r = (1 << self.lms.h) + q
        path = []
        for _ in range(self.lms.h):
            path.append(self.tree[r ^ 1])   # fratello del nodo corrente
            r >>= 1
        return path

    def sign_with_index(self, message: bytes, q: int, C: bytes | None = None,
                        **ots_kwargs) -> bytes:
        """Firma con la chiave one-time di indice q (NON aggiorna lo stato).

        Uso interno / test: in produzione si usa sign(), che avanza q.
        """
        ots_sig = self.ots_key(q).sign(message, C=C, **ots_kwargs)
        return (u32str(q) + ots_sig + u32str(self.lms.typecode)
                + b"".join(self.auth_path(q)))

    def sign(self, message: bytes, C: bytes | None = None) -> bytes:
        if self.q >= (1 << self.lms.h):
            raise KeyExhausted("chiave LMS esaurita: tutte le 2^h firme sono state usate")
        q = self.q
        self.q += 1          # lo stato avanza PRIMA di produrre la firma
        return self.sign_with_index(message, q, C)


class LmsPublicKey:
    def __init__(self, lms: LmsParams, ots: LmotsParams, I: bytes, root: bytes):
        self.lms, self.ots, self.I, self.root = lms, ots, I, root

    def serialize(self) -> bytes:
        return (u32str(self.lms.typecode) + u32str(self.ots.typecode)
                + self.I + self.root)

    @classmethod
    def deserialize(cls, data: bytes) -> "LmsPublicKey":
        if len(data) < 8:
            raise InvalidSignature("chiave pubblica troppo corta")
        lms_t, ots_t = strTou32(data[:4]), strTou32(data[4:8])
        if lms_t not in LMS or ots_t not in LMOTS:
            raise InvalidSignature("typecode sconosciuto")
        lms = LMS[lms_t]
        if len(data) != lms.pub_len:
            raise InvalidSignature("lunghezza chiave pubblica errata")
        return cls(lms, LMOTS[ots_t], data[8:24], data[24:24 + lms.m])

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            return self._root_candidate(message, signature) == self.root
        except InvalidSignature:
            return False

    def _root_candidate(self, message: bytes, sig: bytes) -> bytes:
        """Algoritmo 6a dell'RFC: ricalcola la radice candidata Tc."""
        if len(sig) < 8:
            raise InvalidSignature("firma troppo corta")
        q = strTou32(sig[:4])
        ots_t = strTou32(sig[4:8])
        if ots_t != self.ots.typecode:
            raise InvalidSignature("typecode LM-OTS diverso da quello della chiave")
        ots_len = self.ots.sig_len
        if len(sig) < 4 + ots_len + 4:
            raise InvalidSignature("firma troppo corta")
        ots_sig = sig[4:4 + ots_len]
        lms_t = strTou32(sig[4 + ots_len: 8 + ots_len])
        if lms_t != self.lms.typecode:
            raise InvalidSignature("typecode LMS diverso da quello della chiave")
        h, m = self.lms.h, self.lms.m
        if q >= (1 << h) or len(sig) != self.lms.sig_len(self.ots):
            raise InvalidSignature("q fuori intervallo o lunghezza errata")
        path_bytes = sig[8 + ots_len:]
        path = [path_bytes[i * m:(i + 1) * m] for i in range(h)]

        Kc = candidate_public_key(self.ots.typecode, self.I, q, message, ots_sig)
        r = (1 << h) + q
        tmp = leaf_hash(self.I, r, Kc)
        for sibling in path:
            if r % 2 == 1:   # nodo destro: il fratello sta a sinistra
                tmp = node_hash(self.I, r // 2, sibling, tmp)
            else:            # nodo sinistro: il fratello sta a destra
                tmp = node_hash(self.I, r // 2, tmp, sibling)
            r //= 2
        return tmp


def lms_sig_length_from_bytes(sig: bytes) -> int:
    """Lunghezza di una firma LMS letta dai typecode contenuti (serve per HSS)."""
    if len(sig) < 8:
        raise InvalidSignature("firma troppo corta")
    ots_t = strTou32(sig[4:8])
    if ots_t not in LMOTS:
        raise InvalidSignature("typecode LM-OTS sconosciuto")
    ots = LMOTS[ots_t]
    off = 4 + ots.sig_len
    if len(sig) < off + 4:
        raise InvalidSignature("firma troppo corta")
    lms_t = strTou32(sig[off:off + 4])
    if lms_t not in LMS:
        raise InvalidSignature("typecode LMS sconosciuto")
    return LMS[lms_t].sig_len(ots)
