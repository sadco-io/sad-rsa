#!/usr/bin/python3
"""
Ciphertext generation for testing an RSA-OAEP decryption interface.

This wraps the toolkit's step2.py and adds one probe, `valid_oaep`, which the toolkit does
not have: a correctly padded RSAES-OAEP ciphertext (SHA-256, MGF1-SHA-256, empty label).
The classes the toolkit recommends for OAEP are all rejected by an OAEP decryption, so
without this probe a run compares failure paths only.

Usage is the same as step2.py:
    oaep_step2.py -c cert.pem -o out_dir --repeat N [--verbose] probe[="p1 p2"] ...
"""

import getopt
import hashlib
import os
import random
import sys

import step2
from step2 import CiphertextGenerator

H_LEN = hashlib.sha256().digest_size


def mgf1(seed, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def valid_oaep(self, m_length):
    """
    A valid RSAES-OAEP ciphertext (RFC 8017 section 7.1.1) with SHA-256 for the hash and
    for MGF1, an empty label, and a random message of the given length.
    """
    k = self.key_size
    if m_length > k - 2 * H_LEN - 2:
        raise ValueError("Too big message size, max size: {0}".format(
            k - 2 * H_LEN - 2))
    message = bytes(random.choices(range(256), k=m_length))
    l_hash = hashlib.sha256(b"").digest()
    db = l_hash + bytes(k - m_length - 2 * H_LEN - 2) + b"\x01" + message
    seed = bytes(random.choices(range(256), k=H_LEN))
    masked_db = bytes(a ^ b for a, b in zip(db, mgf1(seed, k - H_LEN - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, mgf1(masked_db, H_LEN)))
    return self.encrypt_plaintext(b"\x00" + masked_seed + masked_db)


CiphertextGenerator.types["valid_oaep"] = 1
CiphertextGenerator.valid_oaep = valid_oaep


def main():
    cert = None
    out_dir = "ciphertexts"
    repeat = None
    verbose = False

    opts, args = getopt.getopt(sys.argv[1:], "c:o:", ["repeat=", "verbose"])
    for opt, arg in opts:
        if opt == "-c":
            cert = arg
        elif opt == "-o":
            out_dir = arg
        elif opt == "--repeat":
            repeat = int(arg)
        elif opt == "--verbose":
            verbose = True

    if not args or not cert or not repeat or repeat <= 0:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    pub = step2.get_key(cert)
    print("working with {0}bit key".format(len(pub)))
    print("Will save ciphertexts to {0}".format(out_dir))
    os.mkdir(out_dir)
    step2.gen_timing_probes(out_dir, pub, args, repeat, verbose)


if __name__ == '__main__':
    main()
