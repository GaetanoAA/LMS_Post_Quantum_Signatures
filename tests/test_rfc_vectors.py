"""
Validazione sui vettori di test ufficiali dell'RFC 8554 (Appendice F).

- Test Case 1: verifica di una firma HSS a 2 livelli (H5/W8 + H5/W8).
- Test Case 2: oltre alla verifica, l'RFC fornisce SEED e I della chiave
  privata. Rigeneriamo le chiavi con la nostra implementazione e
  riproduciamo la firma BYTE PER BYTE (usando lo stesso randomizzatore C).
"""
import json
import os
import unittest

from lms import LMS_BY_H, LMOTS_BY_W, LmsPrivateKey, hss_verify
from lms.params import u32str

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "rfc8554_vectors.json")) as f:
    V = {k: bytes.fromhex(v) for k, v in json.load(f).items() if not k.startswith("_")}


class TestRfcVectors(unittest.TestCase):
    def test_case_1_verify(self):
        self.assertTrue(hss_verify(V["tc1_pub"], V["tc1_msg"], V["tc1_sig"]))

    def test_case_2_verify(self):
        self.assertTrue(hss_verify(V["tc2_pub"], V["tc2_msg"], V["tc2_sig"]))

    def test_tampered_signatures_rejected(self):
        for name in ("tc1", "tc2"):
            sig = V[f"{name}_sig"]
            for pos in (10, 200, len(sig) // 2, len(sig) - 1):
                bad = bytearray(sig)
                bad[pos] ^= 0x01
                with self.subTest(case=name, byte=pos):
                    self.assertFalse(hss_verify(V[f"{name}_pub"], V[f"{name}_msg"], bytes(bad)))
            self.assertFalse(hss_verify(V[f"{name}_pub"], V[f"{name}_msg"] + b"!", sig))

    def test_case_2_keygen_and_exact_signature(self):
        priv = V["tc2_priv"]
        seed1, I1, seed2, I2 = priv[:32], priv[32:48], priv[48:80], priv[80:96]

        # Livello 1: LMS_SHA256_M32_H10 + LMOTS_SHA256_N32_W4
        top = LmsPrivateKey(LMS_BY_H[10], LMOTS_BY_W[4], I1, seed1)
        self.assertEqual(u32str(2) + top.public_key().serialize(), V["tc2_pub"])

        # Livello 2: LMS_SHA256_M32_H5 + LMOTS_SHA256_N32_W8
        child = LmsPrivateKey(LMS_BY_H[5], LMOTS_BY_W[8], I2, seed2)
        child_pub = child.public_key().serialize()

        # Struttura della firma: Nspk | sig[0] (H10/W4) | pub[1] | sig finale (H5/W8)
        sig = V["tc2_sig"]
        len0 = LMS_BY_H[10].sig_len(LMOTS_BY_W[4])
        sig0 = sig[4:4 + len0]
        pub1 = sig[4 + len0: 4 + len0 + len(child_pub)]
        final = sig[4 + len0 + len(child_pub):]
        self.assertEqual(pub1, child_pub)

        # Ri-firmiamo con gli stessi q e C: deve uscire la stessa identica firma
        q0, C0 = int.from_bytes(sig0[:4], "big"), sig0[8:40]
        q1, C1 = int.from_bytes(final[:4], "big"), final[8:40]
        self.assertEqual(top.sign_with_index(child_pub, q0, C=C0), sig0)
        self.assertEqual(child.sign_with_index(V["tc2_msg"], q1, C=C1), final)


if __name__ == "__main__":
    unittest.main(verbosity=2)
