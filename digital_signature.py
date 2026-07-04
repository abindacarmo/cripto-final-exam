"""
RSA Digital Signature Scheme — Message Digest Authentication
Zeny (SENDER, signs) -> Jacky (RECEIVER, verifies)

Parameter rules (from the Turma A assignment):
- p, q  : chosen freely by you, MUST be different from your classmates' values
- M     : any message, here using your own name
- h     : hash of M, can be computed automatically with SHA-256 (Python)
          OR entered manually from an online hashing tool

Important note:
Real RSA uses a very large modulus n (2048-bit+), while a SHA-256 hash
is also large (256-bit). Since p and q are allowed to be small for
manual practice in this assignment, the hash result is first reduced
with `mod n` so it fits within the RSA modulus range. This is ONLY for
demonstration/practice purposes, not secure production RSA.
"""

import hashlib
from math import gcd


# ---------------------------------------------------------
# 1. Helper: check for a prime number (used to validate p, q)
# ---------------------------------------------------------
def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True


def input_prime(prompt: str) -> int:
    """Keep asking until the user enters a valid prime number."""
    while True:
        raw = input(prompt).strip()
        try:
            value = int(raw)
        except ValueError:
            print("Please enter a whole number.")
            continue

        if not is_prime(value):
            print(f"{value} is not a prime number. Please try again.")
            continue

        return value


# ---------------------------------------------------------
# 2. Key generation (RSA)
# ---------------------------------------------------------
def generate_keys(p: int, q: int, e: int = 17):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must be prime numbers!")
    if p == q:
        raise ValueError("p and q must not be equal!")

    n = p * q
    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} is not coprime with phi(n)={phi}, choose another e.")

    d = pow(e, -1, phi)  # modular inverse -> private key exponent

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key, phi


# ---------------------------------------------------------
# 3. Hash the message -> convert to integer, then mod n
#    There are now 2 modes: automatic (Python SHA-256) / manual (online tool)
# ---------------------------------------------------------
def hash_message_auto(message: str, n: int):
    digest_hex = hashlib.sha256(message.encode()).hexdigest()
    h_full = int(digest_hex, 16)
    h_mod_n = h_full % n
    return h_mod_n, digest_hex, "automatic (Python hashlib.sha256)"


def hash_message_manual(digest_hex: str, n: int):
    digest_hex = digest_hex.strip().lower()
    h_full = int(digest_hex, 16)
    h_mod_n = h_full % n
    return h_mod_n, digest_hex, "manual (entered from an online hashing tool)"


def choose_hash_method(message: str, n: int):
    print("\nChoose the hashing method for M:")
    print("1. Compute automatically with Python (SHA-256)")
    print("2. Enter a hex digest manually from an online hash generator (e.g. SHA-256)")
    choice = input(">> ").strip()

    if choice == "2":
        digest_hex = input("Enter the hex digest from the online hashing tool: ").strip()
        return hash_message_manual(digest_hex, n)
    else:
        return hash_message_auto(message, n)


# ---------------------------------------------------------
# 4. Signing (done by Zeny, using the PRIVATE key)
# ---------------------------------------------------------
def sign(h: int, private_key: tuple):
    d, n = private_key
    signature = pow(h, d, n)
    return signature


# ---------------------------------------------------------
# 5. Verifying (done by Jacky, using the PUBLIC key)
#    Jacky receives (M, S), then re-hashes M
# ---------------------------------------------------------
def verify(h_received: int, signature: int, public_key: tuple) -> tuple:
    e, n = public_key
    h_from_signature = pow(signature, e, n)
    return h_received == h_from_signature, h_from_signature


def print_line(title: str = ""):
    width = 78
    if title:
        print(f"\n{title}")
    print("-" * width)


def display_char(char: str) -> str:
    if char == " ":
        return "SPACE"
    return char


def normalize_message(message: str) -> str:
    return message.upper().replace(" ", "")


def print_message_blocks(message: str):
    print_line("1. MESSAGE BLOCKS")
    print(f'Message M = "{message}"')
    print("Each character is treated as one input block before hashing.")

    for index, char in enumerate(message, start=1):
        ascii_value = ord(char)
        hex_value = f"{ascii_value:02X}"
        binary_value = f"{ascii_value:08b}"
        print(f"\nBlock {index}: character {display_char(char)}")
        print(f"Character = {display_char(char)}")
        print(f"ASCII({display_char(char)}) = {ascii_value}")
        print(f"Hex = {ascii_value} = {hex_value}")
        print(f"Binary = {ascii_value} = {binary_value}")

    print("\nByte sequence fed into hashing:")
    print(" ".join(f"{ord(char):02X}" for char in message))


def modular_power_steps(base: int, exponent: int, modulus: int):
    """Return left-to-right square-and-multiply steps."""
    bits = bin(exponent)[2:]
    result = 1
    current_base = base % modulus
    steps = []

    for bit in bits:
        before_square = result
        after_square = (result * result) % modulus
        if bit == "1":
            after_multiply = (after_square * current_base) % modulus
            action = f"({after_square} * {current_base}) mod {modulus}"
        else:
            after_multiply = after_square
            action = "no multiply"

        steps.append({
            "bit": bit,
            "before": before_square,
            "after_square": after_square,
            "action": action,
            "result": after_multiply,
        })
        result = after_multiply

    return bits, steps, result


def print_modular_power_report(title: str, base: int, exponent: int, modulus: int, symbol: str):
    bits, steps, result = modular_power_steps(base, exponent, modulus)

    print_line(title)
    print(f"{symbol} = {base}^{exponent} mod {modulus}")
    print(f"Exponent in binary = {exponent} = {bits}_2")

    for index, item in enumerate(steps, start=1):
        print(f"\nStep {index}: bit = {item['bit']}")
        print(f"Value before squaring = {item['before']}")
        print(f"Square = {item['before']}^2 mod {modulus} = {item['after_square']}")
        if item["bit"] == "1":
            print(f"Since bit = 1, multiply by the base:")
            print(f"Result = {item['action']} = {item['result']}")
        else:
            print("Since bit = 0, no multiplication by the base.")
            print(f"Result = {item['result']}")

    print(f"\nFinal result: {symbol} = {result}")
    return result


def print_key_report(p: int, q: int, e: int, n: int, phi: int, d: int):
    print_line("0. KEY GENERATION (by Zeny)")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"n = p * q = {p} * {q} = {n}")
    print(f"phi(n) = (p - 1)(q - 1) = {p - 1} * {q - 1} = {phi}")
    print(f"e = {e}")
    print(f"gcd(e, phi(n)) = gcd({e}, {phi}) = {gcd(e, phi)}")
    print(f"d = e^(-1) mod phi(n) = {e}^(-1) mod {phi} = {d}")
    print(f"Zeny's public key  = (e, n) = ({e}, {n})")
    print(f"Zeny's private key = (d, n) = ({d}, {n})")


def detect_hash_algorithm(digest_hex: str) -> str:
    length = len(digest_hex.strip())
    if length == 32:
        return "MD5 (128-bit)"
    elif length == 40:
        return "SHA-1 (160-bit)"
    elif length == 64:
        return "SHA-256 (256-bit)"
    elif length == 128:
        return "SHA-512 (512-bit)"
    else:
        return f"unknown ({length} hex chars / {length * 4}-bit)"


def print_hash_report(n: int, digest_hex: str, h: int, method_label: str):
    h_full = int(digest_hex, 16)
    algorithm = detect_hash_algorithm(digest_hex)

    print_line("2. MESSAGE DIGEST")
    print(f"Hashing method = {method_label}")
    print(f"Detected hash algorithm = {algorithm}  (based on hex digest length)")
    print()
    print("Formula:")
    print(f"digest = HASH(M)   [{algorithm}]")
    print("h = digest mod n")
    print()
    print(f"HASH(M) in hex = {digest_hex}")
    print(f"HASH(M) in decimal = {h_full}")
    print(f"h = HASH(M) mod n = {h_full} mod {n} = {h}")
    print()
    print("Why the 'mod n' step is needed:")
    print(f"- The raw hash ({algorithm}) is a VERY large number")
    print(f"  ({h_full} , {len(str(h_full))} decimal digits).")
    print(f"- The RSA modulus n = {n} in this assignment is deliberately kept")
    print("  small so it can be computed manually (small p and q, not 2048-bit")
    print("  like real RSA).")
    print("- Since h must be smaller than n to be used in the RSA modular")
    print("  exponentiation (h^d mod n), the hash digest is reduced with mod n")
    print("  before signing.")
    print(f"- So: h = HASH(M) mod n = {h}  <-- this is what Zeny actually")
    print("  signs, NOT the full raw hash digest.")


def print_preprocessing_report(original_message: str, normalized_message: str):
    print_line("MESSAGE PREPROCESSING")
    print(f'Original message = "{original_message}"')
    print("Step 1: convert all lowercase letters to uppercase")
    print(f'Uppercase = "{original_message.upper()}"')
    print("Step 2: remove all spaces")
    print(f'Message M = "{normalized_message}"')


def print_sent_data(message: str, signature: int):
    print_line("DATA SENT FROM ZENY -> JACKY")
    print(f"M = {message}")
    print(f"S = {signature}")
    print(f"Package sent = M + S = {message} + {signature}")


def print_verification_report(message: str, signature: int, public_key: tuple, digest_hex: str, h_expected: int):
    e, n = public_key

    print_line("4. VERIFICATION (by Jacky)")
    print("Jacky receives M and S from Zeny, then re-hashes M:")
    print(f'Received M = "{message}"')
    print(f"HASH(M) in hex = {digest_hex}")
    print(f"h_received = HASH(M) mod n = {h_expected}")

    h_from_signature = print_modular_power_report(
        "Opening the signature with Zeny's public key",
        signature,
        e,
        n,
        "h_from_signature",
    )

    print_line("5. COMPARISON")
    print(f"h_received       = {h_expected}")
    print(f"h_from_signature = h' = S^e mod n = {h_from_signature}")
    is_valid = h_expected == h_from_signature
    print(f"Is h = h'? {h_expected} == {h_from_signature} -> {is_valid}")
    if is_valid:
        print("Conclusion: the digital signature is VALID, the message was not altered.")
    else:
        print("Conclusion: the digital signature is INVALID / the message was altered.")
    return is_valid


# ---------------------------------------------------------
# DEMO — p, q, and the message are entered by you at runtime
# ---------------------------------------------------------
if __name__ == "__main__":
    print("=" * 78)
    print("RSA DIGITAL SIGNATURE DEMO - ZENY (SENDER) -> JACKY (RECEIVER)")
    print("=" * 78)

    # --- self-determined parameters (MUST differ from classmates) ---
    print("\nEnter your own prime numbers p and q (must be different from your classmates').")
    p = input_prime("p = ")
    q = input_prime("q = ")
    while q == p:
        print("q must not be equal to p. Please enter a different value.")
        q = input_prime("q = ")

    original_message = input("Enter message (your name): ")
    message = normalize_message(original_message)

    public_key, private_key, phi = generate_keys(p, q)
    e, n = public_key
    d, _ = private_key

    print_key_report(p, q, e, n, phi, d)
    print_preprocessing_report(original_message, message)
    print_message_blocks(message)

    # --- Zeny: hash M, then sign ---
    h, digest_hex, method_label = choose_hash_method(message, n)
    print_hash_report(n, digest_hex, h, method_label)

    signature_manual = print_modular_power_report(
        "3. SIGNING (by Zeny)",
        h,
        d,
        n,
        "S",
    )
    signature = sign(h, private_key)
    print(f"Check with Python's pow: S = {signature}")

    # --- Data sent to Jacky ---
    print_sent_data(message, signature)

    # --- Jacky: re-hash the received M, then verify ---
    h_received, digest_hex_received, _ = hash_message_auto(message, n) \
        if method_label.startswith("automatic") else hash_message_manual(digest_hex, n)
    is_valid = print_verification_report(message, signature, public_key, digest_hex_received, h_received)

    # --- Simulation: message slightly altered (tampered) -> verification must FAIL ---
    tampered_message = message + "O"
    h_tampered, digest_hex_tampered, _ = hash_message_auto(tampered_message, n)
    is_valid_tampered, _ = verify(h_tampered, signature, public_key)

    print_line("6. TAMPER TEST")
    print(f'Original message = "{message}"')
    print(f'Tampered message = "{tampered_message}"')
    print(f"Verification of original message -> {is_valid}")
    print(f"Verification of tampered message -> {is_valid_tampered}")
    print("=" * 78)
    