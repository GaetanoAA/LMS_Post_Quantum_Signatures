"""Test funzionali di LM-OTS, LMS e della gestione dello stato."""
import os
import tempfile
import unittest

from lms import (LMOTS, LMS_BY_H, LMOTS_BY_W, LmotsPrivateKey, LmsPrivateKey,
                 LmsPublicKey, KeyExhausted, StatefulSigner)
from lms.params import compute_p_ls


class TestParams(unittest.TestCase):
    def test_table1_p_and_ls(self):
        """p e ls della Tabella 1 coincidono con la formula dell'Appendice B."""
        for P in LMOTS.values():
            self.assertEqual(compute_p_ls(P.n, P.w), (P.p, P.ls), P.name)


class TestLmots(unittest.TestCase):
    def test_sign_verify_all_w(self):
        for w in (1, 2, 4, 8):
            with self.subTest(w=w):
                sk = LmotsPrivateKey.generate(LMOTS_BY_W[w])
                pk = sk.public_key()
                sig = sk.sign(b"ciao")
                self.assertEqual(len(sig), LMOTS_BY_W[w].sig_len)
                self.assertTrue(pk.verify(b"ciao", sig))
                self.assertFalse(pk.verify(b"ciao!", sig))

    def test_reuse_is_blocked(self):
        sk = LmotsPrivateKey.generate(LMOTS_BY_W[8])
        sk.sign(b"primo")
        with self.assertRaises(RuntimeError):
            sk.sign(b"secondo")


class TestLms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sk = LmsPrivateKey.generate(LMS_BY_H[5], LMOTS_BY_W[4])
        cls.pk = cls.sk.public_key()

    def test_all_leaves(self):
        """Tutte le 32 chiavi one-time producono firme valide."""
        sk = LmsPrivateKey(self.sk.lms, self.sk.ots, self.sk.I, self.sk.seed)
        for q in range(32):
            msg = f"messaggio {q}".encode()
            sig = sk.sign(msg)
            self.assertEqual(int.from_bytes(sig[:4], "big"), q)
            self.assertTrue(self.pk.verify(msg, sig))
        with self.assertRaises(KeyExhausted):
            sk.sign(b"uno di troppo")

    def test_public_key_roundtrip(self):
        pk2 = LmsPublicKey.deserialize(self.pk.serialize())
        self.assertEqual(pk2.root, self.pk.root)

    def test_wrong_path_or_q_rejected(self):
        sig = bytearray(self.sk.sign_with_index(b"m", 7))
        self.assertTrue(self.pk.verify(b"m", bytes(sig)))
        bad_q = bytes(sig[:3]) + bytes([8]) + bytes(sig[4:])
        self.assertFalse(self.pk.verify(b"m", bad_q))
        sig[-1] ^= 1   # altera l'ultimo nodo del percorso di autenticazione
        self.assertFalse(self.pk.verify(b"m", bytes(sig)))
        self.assertFalse(self.pk.verify(b"m", bytes(sig[:-1])))   # troncata


class TestState(unittest.TestCase):
    def test_counter_persisted_before_signature(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "key.json")
            s = StatefulSigner.create(path, LMS_BY_H[5].typecode, LMOTS_BY_W[8].typecode)
            pk = s.public_key()
            sig1 = s.sign(b"a")
            # un nuovo processo che riapre la chiave riparte dall'indice giusto
            s2 = StatefulSigner(path)
            sig2 = s2.sign(b"b")
            self.assertEqual(sig1[:4], (0).to_bytes(4, "big"))
            self.assertEqual(sig2[:4], (1).to_bytes(4, "big"))
            self.assertTrue(pk.verify(b"a", sig1) and pk.verify(b"b", sig2))
            self.assertEqual(s2.remaining, 30)

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "key.json")
            StatefulSigner.create(path, 5, 4)
            with self.assertRaises(FileExistsError):
                StatefulSigner.create(path, 5, 4)


if __name__ == "__main__":
    unittest.main(verbosity=2)
