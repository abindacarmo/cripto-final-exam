import ast
from secrets import randbelow

# Public key: (p, g, y)
P = int(input("input your key: "))
G = int(input("input your key: "))
Y = int(input("input your key: "))

# Private key: x
X = 123
DEFAULT_K = 50
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHAR_TO_NUMBER = {char: number for number, char in enumerate(ALPHABET)}
NUMBER_TO_CHAR = {number: char for number, char in enumerate(ALPHABET)}

def encrypt_number(m, k=None, p=P, g=G, y=Y):
    """Encrypt one number m using ElGamal."""
    if not 0 <= m < p:
        raise ValueError(f"Message number must be between 0 and {p - 1}")

    # Based on the source formula: 1 <= k <= p-1
    if k is None:
        k = randbelow(p - 1) + 1
    elif not 1 <= k <= p - 1:
        raise ValueError(f"k must be between 1 and {p - 1}")
    
    c1 = pow(g, k, p)
    # Compute b = (y^k * m) mod p based on the ElGamal formula.
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def decrypt_number(cipher_pair, p=P, x=X):
    """Decrypt one ElGamal cipher pair."""
    c1, c2 = cipher_pair
    # Compute (a^x)^-1 mod p based on the ElGamal decryption step.
    shared_secret_inverse = pow(c1, p - 1 - x, p) 
    return (c2 * shared_secret_inverse) % p

def encrypt_message(message):
    """Encrypt a text message as UTF-8 bytes."""
    message_bytes = message.encode("utf-8")
    return [encrypt_number(byte) for byte in message_bytes]

def decrypt_message(ciphertext):
    """Decrypt a list of (c1, c2) pairs into text."""
    decrypted_bytes = bytes(decrypt_number(pair) for pair in ciphertext)
    return decrypted_bytes.decode("utf-8")

def normalize_table_message(message):
    """Uppercase the message and remove all spaces before encryption."""
    return message.upper().replace(" ", "")

def text_to_numbers(message):
    """Convert text using A=0, B=1, ..., Z=25 after removing spaces."""
    normalized_message = normalize_table_message(message)
    numbers = []
    for char in normalized_message:
        if char not in CHAR_TO_NUMBER:
            raise ValueError(f"Unsupported character: {char!r}")
        numbers.append(CHAR_TO_NUMBER[char])
    return numbers

def numbers_to_text(numbers):
    """Convert numbers back using A=0, B=1, ..., Z=25."""
    chars = []
    for number in numbers:
        if number not in NUMBER_TO_CHAR:
            raise ValueError(f"Number cannot be converted to a letter: {number}")
        chars.append(NUMBER_TO_CHAR[number])
    return "".join(chars)

def encrypt_table_message(message, k=None):
    """Encrypt text after uppercasing and removing spaces.

    If k is None, every character gets a different random k.
    """
    return [encrypt_number(number, k) for number in text_to_numbers(message)]

def encrypt_table_message_details(message, fixed_k=None):
    """Return encryption details for each character."""
    normalized_message = normalize_table_message(message)
    numbers = text_to_numbers(message)
    details = []

    for char, number in zip(normalized_message, numbers):
        k = fixed_k if fixed_k is not None else randbelow(P - 1) + 1
        a, b = encrypt_number(number, k)
        multiplier = pow(Y, k, P)
        details.append({
            "char": char,
            "m": number,
            "k": k,
            "a": a,
            "multiplier": multiplier,
            "b": b,
            "ciphertext": (a, b),
        })

    return details

def decrypt_table_message(ciphertext):
    """Decrypt table-style ciphertext back to text."""
    numbers = [decrypt_number(pair) for pair in ciphertext]
    return numbers_to_text(numbers)

def decrypt_table_message_details(ciphertext):
    """Return decryption details for each cipher pair."""
    details = []

    for a, b in ciphertext:
        shared_secret = pow(a, X, P)
        shared_secret_inverse = pow(shared_secret, -1, P)
        m = (b * shared_secret_inverse) % P
        char = NUMBER_TO_CHAR.get(m, "?")
        details.append({
            "a": a,
            "b": b,
            "shared_secret": shared_secret,
            "shared_secret_inverse": shared_secret_inverse,
            "m": m,
            "char": char,
            "ciphertext": (a, b),
        })

    return details

def print_line(title=""):
    width = 72
    if title:
        print(f"\n{title}")
    print("-" * width)

def print_encryption_report(original_message, normalized_message, details, fixed_k=None):
    print_line("KEY DATA")
    print(f"Public key  : p = {P}, g = {G}, y = {Y}")
    print(f"Private key : x = {X}")
    if fixed_k is None:
        print("Random value: k is different for each letter")
    else:
        print(f"Random value: k = {fixed_k}")

    print_line("MESSAGE PREPROCESSING")
    print(f"Original message                   : {original_message}")
    print(f"After uppercase and removing spaces: {normalized_message}")
    print("Conversion                         : A=0, B=1, ..., Z=25")

    print_line("ELGAMAL ENCRYPTION FORMULA")
    print("a = g^k mod p")
    print("b = (y^k * m) mod p")
    print("ciphertext = (a, b)")

    print_line("MAIN COMPUTATION")
    if fixed_k is None:
        print("Because k is different for each letter, a and y^k mod p are also different.")
        print("The computation details are shown in the table below.")
    elif details:
        first = details[0]
        print(f"a = {G}^{fixed_k} mod {P} = {first['a']}")
        print(f"y^k mod p = {Y}^{fixed_k} mod {P} = {first['multiplier']}")
        print(f"So b = ({first['multiplier']} * m) mod {P}")

    print_line("ENCRYPTION TABLE")
    print(f"{'No':>2} | {'Letter':^6} | {'m':>2} | {'k':>4} | {'a':>4} | {'y^k mod p':>9} | {'b':>4} | {'Ciphertext (a,b)':<18}")
    print("-" * 92)
    for index, item in enumerate(details, start=1):
        ciphertext = f"({item['a']}, {item['b']})"
        print(
            f"{index:>2} | {item['char']:^6} | {item['m']:>2} | {item['k']:>4} | "
            f"{item['a']:>4} | {item['multiplier']:>9} | {item['b']:>4} | {ciphertext:<18}"
        )

    print_line("CIPHERTEXT LIST")
    print([item["ciphertext"] for item in details])

    print_block_report(details)

def print_block_report(details):
    print_line("WRITTEN VERSION BY BLOCK")
    for block_index, start in enumerate(range(0, len(details), 2), start=1):
        block_items = details[start:start + 2]
        block_text = "".join(item["char"] for item in block_items)
        print(f"\nBlock {block_index}: letters {block_text}")

        for item in block_items:
            print(f"\nLetter {item['char']}:")
            print(f"m = {item['char']} = {item['m']}, k = {item['k']}")
            print(f"a = {G}^{item['k']} mod {P} = {item['a']}")
            print(f"y^k mod p = {Y}^{item['k']} mod {P} = {item['multiplier']}")
            print(f"b = ({item['multiplier']} * {item['m']}) mod {P} = {item['b']}")
            print(f"Ciphertext = ({item['a']}, {item['b']})")

def print_decryption_report(details):
    plaintext = "".join(item["char"] for item in details)

    print_line("KEY DATA")
    print(f"Private key : x = {X}")
    print(f"Modulus     : p = {P}")

    print_line("ELGAMAL DECRYPTION FORMULA")
    print("ciphertext = (a, b)")
    print("s = a^x mod p")
    print("s_inverse = s^(-1) mod p")
    print("m = (b * s_inverse) mod p")
    print("Result conversion: A=0, B=1, ..., Z=25")

    print_line("DECRYPTION RESULT")
    print(f"Plaintext numbers : {[item['m'] for item in details]}")
    print(f"Plaintext letters : {plaintext}")

    print_line("WRITTEN DECRYPTION VERSION BY BLOCK")
    for block_index, start in enumerate(range(0, len(details), 2), start=1):
        block_items = details[start:start + 2]
        block_text = "".join(item["char"] for item in block_items)
        print(f"\nBlock {block_index}: letter result {block_text}")

        for item in block_items:
            print(f"\nCiphertext {item['ciphertext']}:")
            print(f"a = {item['a']}, b = {item['b']}, x = {X}, p = {P}")
            print(f"s = {item['a']}^{X} mod {P} = {item['shared_secret']}")
            print(f"s_inverse = {item['shared_secret']}^(-1) mod {P} = {item['shared_secret_inverse']}")
            print(f"m = ({item['b']} * {item['shared_secret_inverse']}) mod {P} = {item['m']}")
            print(f"Letter = {item['m']} = {item['char']}")

def read_cipher_pair():
    c1 = int(input("Enter c1/a: "))
    c2 = int(input("Enter c2/b: "))
    return c1, c2

def main():
    print("ElGamal Encryption and Decryption")
    print(f"Public key  : p={P}, g={G}, y={Y}")
    print(f"Private key : x={X}, p={P}\n")
    print("Choose a menu:")
    print("1. Encrypt a number")
    print("2. Decrypt a number")
    print("3. Encrypt UTF-8 text")
    print("4. Decrypt UTF-8 text")
    print("5. Encrypt text using A=0, ..., Z=25")
    print("6. Decrypt text using A=0, ..., Z=25")
    print()

    choice = input("Choice: ").strip()

    if choice == "1":
        m = int(input(f"Enter number m (0 to {P - 1}): "))
        k_input = input("Enter k or leave blank for random: ").strip()
        k = int(k_input) if k_input else None
        c1, c2 = encrypt_number(m, k)
        print("\nCiphertext:")
        print(f"a/c1 = {c1}")
        print(f"b/c2 = {c2}")

    elif choice == "2":
        pair = read_cipher_pair()
        m = decrypt_number(pair)
        print("\nPlaintext number:")
        print(m)

    elif choice == "3":
        message = input("Enter text message: ")
        encrypted = encrypt_message(message)
        print("\nText ciphertext:")
        print(encrypted)

    elif choice == "4":
        raw_ciphertext = input("Enter text ciphertext, for example [(1, 2), (3, 4)]: ")
        ciphertext = ast.literal_eval(raw_ciphertext)
        decrypted = decrypt_message(ciphertext)
        print("\nPlaintext text:")
        print(decrypted)

    elif choice == "5":
        message = input("Enter A-Z text message: ")
        k_input = input("Enter a fixed k or leave blank for random k per letter: ").strip()
        fixed_k = int(k_input) if k_input else None
        normalized_message = normalize_table_message(message)
        details = encrypt_table_message_details(message, fixed_k)
        print_encryption_report(message, normalized_message, details, fixed_k)

    elif choice == "6":
        raw_ciphertext = input("Enter ciphertext, for example [(812, 3), (812, 51)]: ")
        ciphertext = ast.literal_eval(raw_ciphertext)
        details = decrypt_table_message_details(ciphertext)
        print_decryption_report(details)

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
