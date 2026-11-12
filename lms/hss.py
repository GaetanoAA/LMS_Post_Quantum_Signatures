"""
HSS (Hierarchical Signature System), RFC 8554 sezione 6 — solo la VERIFICA.

Nel progetto HSS non è implementato lato firma: serve per validare
l'implementazione LMS sui vettori di test ufficiali, che sono firme HSS
a due livelli. Una firma HSS è una catena di firme LMS: ogni albero firma
la chiave pubblica dell'albero sottostante, l'ultimo firma il messaggio.
"""
from .params import LMS, strTou32, u32str
from .lms import LmsPublicKey, LmsPrivateKey, lms_sig_length_from_bytes
from .lmots import InvalidSignature


def hss_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        L = strTou32(public_key[:4])
        key = LmsPublicKey.deserialize(public_key[4:])
        Nspk = strTou32(signature[:4])
        if Nspk + 1 != L:
            return False
        rest = signature[4:]
        for _ in range(Nspk):
            sig_len = lms_sig_length_from_bytes(rest)
            sig, rest = rest[:sig_len], rest[sig_len:]
            pub_len = LMS[strTou32(rest[:4])].pub_len
            child, rest = rest[:pub_len], rest[pub_len:]
            if not key.verify(child, sig):   # il padre firma la chiave del figlio
                return False
            key = LmsPublicKey.deserialize(child)
        return key.verify(message, rest)
    except (InvalidSignature, KeyError, IndexError):
        return False


def hss_public_key(top: LmsPrivateKey, levels: int) -> bytes:
    return u32str(levels) + top.public_key().serialize()
