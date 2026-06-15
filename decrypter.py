import hashlib
import struct
from typing import List, Tuple, Union
from cipher import derive_keys, PHI, M

def modInverse(a, m):
    m0 = m
    y, x = 0, 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    return x + m0 if x < 0 else x

D_CUBE = modInverse(3, M - 1)
def cubeRoot(x, m):
    return pow(x, D_CUBE, m)

def reverse_confusion_pass(c_bytes: bytes, initial_state: int) -> bytes:
    s = initial_state
    p = bytearray()
    for i, c_i in enumerate(c_bytes):
        mask = (((s ^ i) & 0xFFFFFFFF) * 31) % 256
        p_i = (c_i ^ mask) & 0xFF
        p.append(p_i)
        term_update = (c_i * i) & 0xFFFFFFFF
        s = ((s + p_i + term_update) & 0xFFFFFFFF) % M
    return bytes(p)

def reverse_twc_pass(x_nodes: List[int], k_a: int, k_b: int, k_c: int, rounds: List[int]) -> List[int]:
    x = list(x_nodes)
    inv_ka = modInverse(k_a, M)
    for r in reversed(rounds):
        # 1. Edge Topology
        edges = [[0] * 8 for _ in range(8)]
        for i in range(8):
            for j in range(8):
                if i == j: continue
                topo_val = ((i * k_a) & 0xFFFFFFFF + (j * k_b) & 0xFFFFFFFF + (r * k_c) & 0xFFFFFFFF) & 0xFFFFFFFF
                if int(topo_val * PHI) % 2 == 1:
                    edges[i][j] = 1

        sinks = [idx for idx, row in enumerate(edges) if sum(row) == 0]
        if not sinks: sinks = [7]

        # 2. Reverse Feedback Recoil
        # R = sum(X_sink) mod M. Since sinks weren't updated, we can just sum them!
        res_vector = sum(x[sink] for sink in sinks) % M
        for i in range(8):
            if i not in sinks:
                # X_new[i] = ((X_old[i] XOR R) * K_A) mod M
                # => X_old[i] = (X_new[i] * inv_ka) XOR R
                val_xor = (x[i] * inv_ka) % M
                x[i] = (val_xor ^ res_vector) & 0xFFFFFFFF

        # 3. Reverse Forward Wavefront Cascade
        for j in range(7, -1, -1):
            for i in range(7, -1, -1):
                if edges[i][j] == 1:
                    root = cubeRoot(x[j], M)
                    mix = (x[i] ^ k_c) & 0xFFFFFFFF
                    x[j] = (root - mix) % M
    return x

def decrypt(ciphertext: bytes, master_key: str) -> bytes:
    k_a, k_b, k_c = derive_keys(master_key)
    s1_init = (k_a ^ k_b) & 0xFFFFFFFF
    s2_init = (k_b ^ k_c) & 0xFFFFFFFF

    plaintext_padded = bytearray()
    prev_cipher = b"\x00" * 32

    for b_idx in range(0, len(ciphertext), 32):
        chunk = ciphertext[b_idx : b_idx + 32]

        # 1. Reverse TWC Rounds 2, 3, 4
        x2 = [struct.unpack(">I", chunk[j*4:(j+1)*4])[0] for j in range(8)]
        x2 = reverse_twc_pass(x2, k_a, k_b, k_c, [2, 3, 4])

        # 2. Reverse Confusion Round 2 (2 passes)
        conf2_p2_bytes = b"".join(struct.pack(">I", node) for node in x2)
        conf2_p1_bytes = reverse_confusion_pass(conf2_p2_bytes, s2_init)
        block_twc1_bytes = reverse_confusion_pass(conf2_p1_bytes, s2_init)

        # 3. Reverse TWC Round 1
        x1 = [struct.unpack(">I", block_twc1_bytes[j*4:(j+1)*4])[0] for j in range(8)]
        x1 = reverse_twc_pass(x1, k_a, k_b, k_c, [1])

        # 4. Reverse Confusion Round 1
        conf1_bytes = b"".join(struct.pack(">I", node) for node in x1)
        mixed_chunk = reverse_confusion_pass(conf1_bytes, s1_init)

        # 5. CBC XOR
        p_chunk = bytes(m ^ p for m, p in zip(mixed_chunk, prev_cipher))
        plaintext_padded.extend(p_chunk)
        prev_cipher = chunk

    if not plaintext_padded: return b""
    pad_len = plaintext_padded[-1]
    return bytes(plaintext_padded[:-pad_len])

if __name__ == "__main__":
    from cipher import encoder
    msg = "The quick brown fox jumps over the lazy dog."
    ct = encoder(msg)
    pt = decrypt(ct, "TWC_CIPHER_MASTER_KEY_2024")
    print(f"Original:  {msg}")
    print(f"Recovered: {pt.decode()}")
