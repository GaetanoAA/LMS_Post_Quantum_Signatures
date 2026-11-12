"""
Parametri e costanti di LMS / LM-OTS secondo RFC 8554 (sezioni 4.1 e 5.1).

Si implementano solo i parametri definiti nell'RFC (SHA-256, n = m = 32 byte).
NIST SP 800-208 aggiunge varianti SHA-256/192 e SHAKE256 che qui non servono.
"""
from dataclasses import dataclass
import struct


# --- Separatori di dominio (RFC 8554, sez. 4.3 e 5.3) ------------------------
D_PBLC = 0x8080  # calcolo della chiave pubblica OTS da y[0..p-1]
D_MESG = 0x8181  # hash del messaggio (randomizzato con C)
D_LEAF = 0x8282  # foglie dell'albero di Merkle
D_INTR = 0x8383  # nodi interni dell'albero di Merkle


@dataclass(frozen=True)
class LmotsParams:
    """Parametri di LM-OTS (Tabella 1 dell'RFC 8554)."""
    typecode: int
    name: str
    n: int    # byte di output dell'hash
    w: int    # bit per cifra di Winternitz (1, 2, 4, 8)
    p: int    # numero di catene = cifre del digest + cifre del checksum
    ls: int   # shift a sinistra del checksum

    @property
    def max_digit(self) -> int:
        return (1 << self.w) - 1

    @property
    def sig_len(self) -> int:
        # u32str(type) || C || y[0] || ... || y[p-1]
        return 4 + self.n * (self.p + 1)


@dataclass(frozen=True)
class LmsParams:
    """Parametri di LMS (Tabella 2 dell'RFC 8554)."""
    typecode: int
    name: str
    m: int    # byte di ciascun nodo dell'albero
    h: int    # altezza dell'albero (2^h firme disponibili)

    def sig_len(self, ots: LmotsParams) -> int:
        # u32str(q) || ots_signature || u32str(type) || path[0..h-1]
        return 4 + ots.sig_len + 4 + self.h * self.m

    @property
    def pub_len(self) -> int:
        # u32str(lms_type) || u32str(ots_type) || I || T[1]
        return 4 + 4 + 16 + self.m


LMOTS = {
    1: LmotsParams(1, "LMOTS_SHA256_N32_W1", 32, 1, 265, 7),
    2: LmotsParams(2, "LMOTS_SHA256_N32_W2", 32, 2, 133, 6),
    3: LmotsParams(3, "LMOTS_SHA256_N32_W4", 32, 4, 67, 4),
    4: LmotsParams(4, "LMOTS_SHA256_N32_W8", 32, 8, 34, 0),
}

LMS = {
    5: LmsParams(5, "LMS_SHA256_M32_H5", 32, 5),
    6: LmsParams(6, "LMS_SHA256_M32_H10", 32, 10),
    7: LmsParams(7, "LMS_SHA256_M32_H15", 32, 15),
    8: LmsParams(8, "LMS_SHA256_M32_H20", 32, 20),
    9: LmsParams(9, "LMS_SHA256_M32_H25", 32, 25),
}

# Comodità: ricerca per w o per h
LMOTS_BY_W = {p.w: p for p in LMOTS.values()}
LMS_BY_H = {p.h: p for p in LMS.values()}


# --- Funzioni di codifica (RFC 8554, sez. 3.1.1) ----------------------------
def u32str(x: int) -> bytes:
    return struct.pack(">I", x)


def u16str(x: int) -> bytes:
    return struct.pack(">H", x)


def u8str(x: int) -> bytes:
    return struct.pack(">B", x)


def strTou32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def compute_p_ls(n: int, w: int) -> tuple[int, int]:
    """Ricalcola p e ls come nell'Appendice B dell'RFC (per verificare la Tabella 1)."""
    u = (8 * n + w - 1) // w
    max_cksum = u * ((1 << w) - 1)
    v = (max_cksum.bit_length() + w - 1) // w
    ls = 16 - v * w
    return u + v, ls
