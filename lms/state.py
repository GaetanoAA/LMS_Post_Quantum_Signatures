"""
Gestione sicura dello stato di una chiave LMS su file.

LMS è uno schema STATEFUL: l'indice q della prossima chiave one-time deve
essere aggiornato in modo persistente PRIMA che la firma lasci il firmatario.
Se si firmasse prima e si salvasse dopo, un crash (o un ripristino da
backup/snapshot) porterebbe a riusare la stessa chiave OTS -> falsificazione
(vedi attacks/attack_ots_reuse.py).

Strategia "reserve-then-sign":
  1. leggi q dal file;
  2. scrivi q+1 su un file temporaneo, fsync, rename atomico;
  3. solo ora calcola e restituisci la firma con indice q.
Un crash tra 2 e 3 "brucia" una chiave (spreco accettabile), ma non la
riusa mai.
"""
import json
import os
import tempfile

from .params import LMS, LMOTS
from .lms import LmsPrivateKey, KeyExhausted


class StatefulSigner:
    def __init__(self, path: str):
        self.path = path
        data = self._load()
        self._key = LmsPrivateKey(
            LMS[data["lms_type"]], LMOTS[data["ots_type"]],
            bytes.fromhex(data["I"]), bytes.fromhex(data["seed"]), data["q"],
        )

    # -- creazione --------------------------------------------------------
    @classmethod
    def create(cls, path: str, lms_type: int, ots_type: int) -> "StatefulSigner":
        if os.path.exists(path):
            raise FileExistsError(f"{path} esiste già: non sovrascrivo una chiave")
        key = LmsPrivateKey.generate(LMS[lms_type], LMOTS[ots_type])
        cls._atomic_write(path, {
            "lms_type": lms_type, "ots_type": ots_type,
            "I": key.I.hex(), "seed": key.seed.hex(), "q": 0,
        })
        return cls(path)

    # -- I/O atomico ------------------------------------------------------
    def _load(self) -> dict:
        with open(self.path) as f:
            return json.load(f)

    @staticmethod
    def _atomic_write(path: str, data: dict) -> None:
        d = os.path.dirname(os.path.abspath(path))
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".lmsstate-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f)
                f.flush()
                os.fsync(f.fileno())           # dati su disco
            os.replace(tmp, path)              # rename atomico
            if hasattr(os, "O_DIRECTORY"):     # fsync della directory (POSIX)
                dfd = os.open(d, os.O_DIRECTORY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    # -- API pubblica -----------------------------------------------------
    def public_key(self):
        return self._key.public_key()

    @property
    def remaining(self) -> int:
        return self._load_q_limit() - self._load()["q"]

    def _load_q_limit(self) -> int:
        return 1 << self._key.lms.h

    def sign(self, message: bytes) -> bytes:
        data = self._load()                    # rilegge sempre lo stato dal disco
        q = data["q"]
        if q >= self._load_q_limit():
            raise KeyExhausted("chiave esaurita")
        data["q"] = q + 1
        self._atomic_write(self.path, data)    # 1) riserva l'indice...
        return self._key.sign_with_index(message, q)   # 2) ...poi firma
