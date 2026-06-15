import hashlib
import struct
from typing import List, Tuple, Union

# Constants from AGENTS.md
M = 4294967291  # 32-bit prime modulus
PHI = 0.618033988749895

def derive_keys(master_key: str) -> Tuple[int, int, int]:
    digest = hashlib.sha256(master_key.encode('utf-8')).digest()
    k_a = struct.unpack(">I", digest[0:4])[0]
    k_b = struct.unpack(">I", digest[4:8])[0]
    k_c = struct.unpack(">I", digest[8:12])[0]
    return k_a, k_b, k_c

def pkcs7_pad(data: bytes, block_size: int = 32) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def confusion_pass(data: bytes, initial_state: int) -> Tuple[bytes, int]:
    """
    State-driven confusion pass:
    mask  = F(state, i) = ((state XOR i) * 31) mod 256
    C[i]  = P[i] XOR mask
    state = G(state, P[i], C[i], i) = (state + P[i] + (C[i] * i)) mod M
    """
    s = initial_state
    result = bytearray()
    for i, p_i in enumerate(data):
        mask = (((s ^ i) & 0xFFFFFFFF) * 31) % 256
        c_i = (p_i ^ mask) & 0xFF
        result.append(c_i)
        term_update = (c_i * i) & 0xFFFFFFFF
        s = ((s + p_i + term_update) & 0xFFFFFFFF) % M
    return bytes(result), s

def phase2_diffusion(x_nodes: List[int], k_a: int, k_b: int, k_c: int, rounds: List[int]) -> List[int]:
    """
    Topological Wavefront Diffusion for a specified list of rounds.
    """
    x = list(x_nodes)
    for r in rounds:
        edges = [[0] * 8 for _ in range(8)]
        for i in range(8):
            for j in range(8):
                if i == j: continue
                topo_val = ((i * k_a) & 0xFFFFFFFF + (j * k_b) & 0xFFFFFFFF + (r * k_c) & 0xFFFFFFFF) & 0xFFFFFFFF
                if int(topo_val * PHI) % 2 == 1:
                    edges[i][j] = 1

        for j in range(8):
            for i in range(8):
                if edges[i][j] == 1:
                    base = x[j] + (x[i] ^ k_c)
                    x[j] = pow(base, 3) % M

        sinks = [idx for idx, row in enumerate(edges) if sum(row) == 0]
        if not sinks: sinks = [7]
        r_vec = sum(x[sink] for sink in sinks) % M

        for i in range(8):
            val_xor = (x[i] ^ r_vec) & 0xFFFFFFFF
            x[i] = (val_xor * k_a) % M
    return x

def encrypt(plaintext: bytes, master_key: str) -> bytes:
    """
    Encrypts plaintext using the updated TWC sequence:
    1. Round 1 Confusion
    2. TWC Round 1
    3. Round 2 Confusion (2 passes)
    4. TWC Rounds 2, 3, 4
    Output is then hex-encoded.
    """
    k_a, k_b, k_c = derive_keys(master_key)
    data = pkcs7_pad(plaintext)

    # State initializations (KeySchedule)
    s1_init = (k_a ^ k_b) & 0xFFFFFFFF
    s2_init = (k_b ^ k_c) & 0xFFFFFFFF

    prev_block = b"\x00" * 32
    ciphertext_bin = bytearray()

    for b_idx in range(0, len(data), 32):
        chunk = data[b_idx : b_idx + 32]
        # CBC XOR
        mixed_chunk = bytes(c ^ p for c, p in zip(chunk, prev_block))

        # 1. Round 1 of confusion
        conf1_bytes, _ = confusion_pass(mixed_chunk, s1_init)

        # 2. Round 1 of topological encryption
        x = [struct.unpack(">I", conf1_bytes[j*4:(j+1)*4])[0] for j in range(8)]
        x = phase2_diffusion(x, k_a, k_b, k_c, [1])

        # 3. Round 2 of confusion (2 passes)
        # Convert back to bytes for confusion pass
        block_twc1 = b"".join(struct.pack(">I", node) for node in x)
        # Pass 1
        conf2_p1, s2 = confusion_pass(block_twc1, s2_init)
        # Pass 2 (After all bytes: C -> second state-driven pass)
        conf2_p2, _ = confusion_pass(conf2_p1, s2_init) # Re-init state for pass 2 per interpretation

        # 4. 3 Rounds of the topological encryption (Rounds 2, 3, 4)
        x2 = [struct.unpack(">I", conf2_p2[j*4:(j+1)*4])[0] for j in range(8)]
        x2 = phase2_diffusion(x2, k_a, k_b, k_c, [2, 3, 4])

        enc_block = b"".join(struct.pack(">I", node) for node in x2)
        ciphertext_bin.extend(enc_block)
        prev_block = enc_block

    # Return raw binary ciphertext bytes
    return bytes(ciphertext_bin)

def encoder(message: str) -> Union[bytes, int]:
    return encrypt(message.encode('utf-8'), "TWC_CIPHER_MASTER_KEY_2024")

if __name__ == "__main__":
    import sys
    msg = sys.argv[1] if len(sys.argv) > 1 else "The quick brown fox jumps over the lazy dog."
    result = encoder(msg)
    if isinstance(result, bytes):
        print(result.hex())
    else:
        print(result)
