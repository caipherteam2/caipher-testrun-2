# AGENTS.MD: HYBRID TWC-CONFUSION CIPHER SPECIFICATION

## 1. Technical Overview
This document defines the architectural specification for a custom, non-linear block cipher. The system processes binary data in deterministic, fixed-size blocks (256-bit payloads split into eight 32-bit words). It consists of two primary operational phases:
1. A stateful, streaming character-level Confusion Phase.
2. A 5-round Topological Wavefront Cascade (TWC) Diffusion Phase based on a dynamic graph model.

## 2. Core Variables & State Space
- Master Key (K): Supplied as input. The implementation must split or derive three independent 32-bit unsigned parameters from it: K_A, K_B, K_C.
- System Modulus (M): Fixed 32-bit prime integer = 4294967291 (2^32 - 5).
- Global State (S): 32-bit unsigned integer initialized to (K_A XOR K_B).
- Golden Ratio Fractional Constant (PHI): Constant float value ~ 0.618033988749895.

## 3. Cryptographic Execution Flow

### Phase 1: Context-Dependent Confusion (1 Round)
This phase iterates sequentially over each ASCII character (C_i) at index (i) inside the input chunk:
1. Generate Dynamic Substitution Value:
   S_sub = ((S XOR i) * 31) mod 256
2. Encrypt the Character:
   E_i = C_i XOR S_sub
3. Update Global State:
   S = (S + C_i + (E_i * i)) mod M
4. Binary Casting:
   Convert the resulting array of encrypted bytes (E) into a contiguous 256-bit binary payload. Divide this block evenly into an array of eight 32-bit unsigned integer nodes: X[0], X[1], ..., X[7].

### Phase 2: Topological Wavefront Diffusion (5 Rounds)
Process the array X through a dynamic directed graph over exactly 5 rounds (r = 1 to 5):

For each round r:
1. Construct Key-Dependent Edge Topology:
   Create an 8x8 adjacency matrix where a directed edge exists from node i to node j if:
   Edge(i, j) = floor((i * K_A + j * K_B + r * K_C) * PHI) mod 2
   Discard all self-loops (where i == j).

2. Forward Wavefront Cascade:
   Loop through target nodes j from 0 to 7 sequentially. For every active Edge(i, j) == 1, update the target node state via a non-associative cubic polynomial twist:
   X[j] = ((X[j] + (X[i] XOR K_C)) ^ 3) mod M

3. Feedback Recoil Pass:
   a. Isolate "sink" nodes (nodes with an out-degree of 0). If no structural sinks are present in this round's topology, default the sink array to contain only X[7].
   b. Sum the current values of the designated sink nodes to compute the Resonance Vector (R):
      R = sum(X_sink) mod M
   c. Invert the edge directions. Propagate a backward wave from target sinks to sources, updating each node:
      X[i] = ((X[i] XOR R) * K_A) mod M

4. Block Reassembly:
   After round 5 concludes, concatenate the internal states of the variables X[0] through X[7] back into a unified 256-bit binary output block.

## 4. Implementation Requirements
- The code must strictly execute operations within unsigned 32-bit integer boundaries to prevent floating-point drift or precision loss.
- Intermediate multiplication states during the cubic calculation (Value ^ 3) must be handled using high-precision data types (like Python's arbitrary-precision integers or JavaScript BigInt) prior to applying the modulus 'M' to avoid overflow truncation.
