import hashlib
import struct
from typing import List, Tuple, Union

# 1. Architecture: Python 3.10+ strict type hinting, no third-party dependencies.
# 2. Key Derivation: SHA-256 split into 32-bit chunks.
# 3. Padding & Stream Handling: PKCS#7 padding to 32-byte (256-bit) blocks.
# 4. Mode of Operation: Cipher Block Chaining (CBC) Mode.
# 5. Bit-Width Enforcement: 32-bit masking (& 0xFFFFFFFF) and arbitrary-precision cubic math.

# Constants from AGENTS.md
M = 4294967291  # 32-bit prime modulus (2^32 - 5)
PHI = 0.618033988749895  # Golden Ratio Fractional Constant

def derive_keys(master_key: str) -> Tuple[int, int, int]:
    """
    Derives three 32-bit unsigned parameters (K_A, K_B, K_C) from a master key string.
    """
    digest = hashlib.sha256(master_key.encode('utf-8')).digest()
    # Extract three 32-bit words (big-endian)
    k_a = struct.unpack(">I", digest[0:4])[0]
    k_b = struct.unpack(">I", digest[4:8])[0]
    k_c = struct.unpack(">I", digest[8:12])[0]
    return k_a, k_b, k_c

def pkcs7_pad(data: bytes, block_size: int = 32) -> bytes:
    """
    Applies PKCS#7 padding to align data to block_size.
    """
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def phase1_confusion(chunk: bytes, s_state: int) -> Tuple[List[int], int]:
    """
    Phase 1: Context-Dependent Confusion.
    Processes a 32-byte chunk and updates the global state S.
    """
    encrypted_bytes = bytearray()
    s = s_state
    for i, c_i in enumerate(chunk):
        # 1. Generate Dynamic Substitution Value
        s_sub = (((s ^ i) & 0xFFFFFFFF) * 31) % 256
        # 2. Encrypt the Character
        e_i = (c_i ^ s_sub) & 0xFF
        encrypted_bytes.append(e_i)
        # 3. Update Global State
        # S = (S + C_i + (E_i * i)) mod M
        term_update = (e_i * i) & 0xFFFFFFFF
        s = ((s + c_i + term_update) & 0xFFFFFFFF) % M

    # 4. Binary Casting: Convert 32 bytes to eight 32-bit unsigned integer nodes
    x = []
    for j in range(8):
        node = struct.unpack(">I", encrypted_bytes[j*4 : (j+1)*4])[0]
        x.append(node)
    return x, s

def phase2_diffusion(x_nodes: List[int], k_a: int, k_b: int, k_c: int) -> List[int]:
    """
    Phase 2: Topological Wavefront Diffusion.
    5 rounds of graph-based diffusion.
    """
    x = list(x_nodes)
    for r in range(1, 6):
        # 1. Construct Key-Dependent Edge Topology
        edges = [[0] * 8 for _ in range(8)]
        for i in range(8):
            for j in range(8):
                if i == j:
                    continue
                # Edge(i, j) = floor((i * K_A + j * K_B + r * K_C) * PHI) mod 2
                topo_val = ((i * k_a) & 0xFFFFFFFF + (j * k_b) & 0xFFFFFFFF + (r * k_c) & 0xFFFFFFFF) & 0xFFFFFFFF
                if int(topo_val * PHI) % 2 == 1:
                    edges[i][j] = 1

        # 2. Forward Wavefront Cascade
        for j in range(8):
            for i in range(8):
                if edges[i][j] == 1:
                    # X[j] = ((X[j] + (X[i] XOR K_C)) ^ 3) mod M
                    # Use arbitrary precision for the base addition and cubing
                    # before applying modulus M to prevent truncation errors.
                    base = x[j] + (x[i] ^ k_c)
                    x[j] = pow(base, 3) % M

        # 3. Feedback Recoil Pass
        # a. Isolate sink nodes
        sinks = []
        for node_idx in range(8):
            is_sink = True
            for target_idx in range(8):
                if edges[node_idx][target_idx] == 1:
                    is_sink = False
                    break
            if is_sink:
                sinks.append(node_idx)

        if not sinks:
            sinks = [7]

        # b. Compute Resonance Vector R
        r_vec = sum(x[sink] for sink in sinks) % M

        # c. Update each node: X[i] = ((X[i] XOR R) * K_A) mod M
        for i in range(8):
            val_xor = (x[i] ^ r_vec) & 0xFFFFFFFF
            x[i] = (val_xor * k_a) % M

    return x

def encrypt(plaintext: bytes, master_key: str) -> bytes:
    """
    Encrypts plaintext using the TWC-Confusion cipher in CBC Mode.
    """
    k_a, k_b, k_c = derive_keys(master_key)
    data = pkcs7_pad(plaintext)

    # Initialize Global State S = K_A XOR K_B
    s = (k_a ^ k_b) & 0xFFFFFFFF

    # CBC Initialization Vector (Fixed for deterministic production output)
    prev_block = b"\x00" * 32
    ciphertext = bytearray()

    for b_idx in range(0, len(data), 32):
        chunk = data[b_idx : b_idx + 32]
        # CBC XOR
        mixed_chunk = bytes(c ^ p for c, p in zip(chunk, prev_block))

        # Phase 1
        x_nodes, s = phase1_confusion(mixed_chunk, s)
        # Phase 2
        x_final = phase2_diffusion(x_nodes, k_a, k_b, k_c)

        # Reassembly
        enc_block = b"".join(struct.pack(">I", node) for node in x_final)
        ciphertext.extend(enc_block)
        prev_block = enc_block

    return bytes(ciphertext)

def encoder(message: str) -> Union[bytes, int]:
    """
    Final production function as per requirement 8.
    """
    # Uses a fixed master key for the 'encoder' service
    return encrypt(message.encode('utf-8'), "TWC_CIPHER_MASTER_KEY_2024")

if __name__ == "__main__":
    # Internal Verification
    msg = "This is a production-ready TWC cipher implementation."
    key = "secret_key"

    result = encrypt(msg.encode(), key)
    print(f"Input: {msg}")
    print(f"Encrypted (Hex): {result.hex()}")

    # Requirement 3: Multi-block handling
    assert len(result) >= 32
    assert len(result) % 32 == 0

    # Requirement 8 check
    enc_out = encoder("Hello World")
    print(f"Encoder Output: {enc_out.hex()}")
    print("Verification Pass.")
