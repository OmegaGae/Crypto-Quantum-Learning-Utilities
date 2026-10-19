# Crypto-Quantum-Learning-Utilities

Code written and tested during my learning path to become a **Cryptography Software Engineer specialised in post-quantum cryptography (PQC)**.

The repository collects two things I built while studying:

- **Classical cryptography from scratch** in Python: historical ciphers and the attacks that break them (brute force, frequency analysis, Kasiski examination, index of coincidence).
- **Quantum computing utilities** with [Qiskit](https://www.ibm.com/quantum/qiskit): helpers to run circuits on IBM Quantum hardware, plus notebooks with first experiments.

> **Educational code only.** Everything here is written to understand how the algorithms work and how they fail. Do not use it to protect real data.

## Why classical cryptography first?

Post-quantum cryptography exists because quantum computers threaten the public-key schemes in use today. To understand that threat, and to evaluate the replacement algorithms, I started with the fundamentals: how a cipher is built, what makes it weak, and how an attacker exploits that weakness. The quantum part of the repository covers the other side of the picture: how quantum circuits are built, run and measured.

## Repository content

| File | Description |
| --- | --- |
| `utils_crypto.py` | Classical ciphers and cryptanalysis tools (see below) |
| `utils.py` | Qiskit / IBM Quantum helpers and a quantum state fidelity function |
| `basic_quantum_circuits.ipynb` | Notebook: introductory quantum circuits with Qiskit |
| `quantum_experimentations.ipynb` | Notebook: further quantum experiments |
| `englisch_words_alpha.txt` | English word list used by the dictionary-based attacks |
| `requirements.txt` | Python dependencies |

### `utils_crypto.py`: ciphers and attacks

**Ciphers**

- Reverse cipher and Atbash
- Caesar cipher in several variants (letters only, custom alphabet, translation-table version, dictionary-based lookup class)
- Transposition ciphers: rail fence (zig-zag) and columnar transposition (plain Python and NumPy versions, with decryption)
- Multiplicative and affine ciphers, with the coprimality check on the key and modular inverse for decryption
- Simple (monoalphabetic) substitution cipher

**Attacks**

- Brute force against Caesar, with timing of each iteration
- Substitution cipher: word-pattern attack that matches the structure of cipher words (e.g. `MISSISSIPPI` -> `0.1.2.2.1.2.2.1.3.3.1`) against a dictionary and narrows the key by intersecting candidate letter mappings
- Vigenère cipher: key length estimation (Kasiski examination combined with the index of coincidence), then recovery of each key letter with a chi-squared test against English letter frequencies

### `utils.py`: quantum utilities

- `get_api_key`: reads the IBM Quantum API key from the system keyring (the key is never stored in the code)
- `check_service_existence`: decorator that checks the `QiskitRuntimeService` account and saves it if missing
- `get_backend`: selects the least busy operational real device with at least 127 qubits, with a fallback by name
- `run_circuit_and_get_counts`: transpiles a circuit for the chosen backend and runs it with the Qiskit Runtime `Sampler`, returning the measurement counts
- `fidelity`: Uhlmann fidelity between two density matrices, with input checks (square, Hermitian, trace 1, positive semidefinite)

## Getting started

Requires **Python 3.12 or newer** (the examples use f-strings with nested quotes).

```bash
git clone https://github.com/OmegaGae/Crypto-Quantum-Learning-Utilities.git
cd Crypto-Quantum-Learning-Utilities
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Run the cryptography examples:

```bash
python utils_crypto.py
```

Open the notebooks:

```bash
jupyter notebook
```

### Running on IBM Quantum hardware (optional)

Store your API key in the keyring once, using the service name and username expected by `utils.py`:

```python
import keyring
keyring.set_password("https://quantum.cloud.ibm.com/", "JulesVerneKey", "<YOUR_IBM_QUANTUM_API_KEY>")
```

Then `get_backend()` and `run_circuit_and_get_counts()` can be used from the notebooks.

## Known limitations

- `SimpleSubstitutionCipher.break_cipher_with_freq_and_dict` runs, but its key recovery is not as accurate as expected: frequency analysis plus dictionary matching only gives partial results.``break_cipher_with_word_pattern`` takes a different approach, based on word structure.
- The word-pattern attack becomes less decisive with a very large dictionary, because more words share the same pattern.
- All ciphers here are historical and insecure by design.

## Roadmap

Planned next steps, moving from the fundamentals toward post-quantum cryptography:

- Lattice-based cryptography basics and a toy Learning With Errors (LWE) example
- Study and experiments with the NIST post-quantum standards: ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)

## Acknowledgements

``englisch_words_alpha.txt`` comes from [schemingduck/english-words-dictionary](https://github.com/schemingduck/english-words-dictionary/blob/master/words_alpha.txt), a fork of dwyl/english-words.

## License

MIT, see `LICENSE`.
