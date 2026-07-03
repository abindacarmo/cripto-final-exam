import ast
from secrets import randbelow

# Public key: (p, g, y)
P = 1009
G = 11
Y = 510

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

    # Sesuai sumber: 1 <= k <= p-1
    if k is None:
        k = randbelow(p - 1) + 1
    elif not 1 <= k <= p - 1:
        raise ValueError(f"k must be between 1 and {p - 1}")
    
    c1 = pow(g, k, p)
    # Menghitung b = (y^k * m) mod p sesuai rumus (3) di sumber
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def decrypt_number(cipher_pair, p=P, x=X):
    """Decrypt one ElGamal cipher pair."""
    c1, c2 = cipher_pair
    # Menghitung (a^x)^-1 mod p sesuai prosedur dekripsi di sumber
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
            raise ValueError(f"Karakter tidak didukung: {char!r}")
        numbers.append(CHAR_TO_NUMBER[char])
    return numbers

def numbers_to_text(numbers):
    """Convert numbers back using A=0, B=1, ..., Z=25."""
    chars = []
    for number in numbers:
        if number not in NUMBER_TO_CHAR:
            raise ValueError(f"Angka tidak bisa dikonversi ke huruf: {number}")
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
    print_line("DATA KUNCI")
    print(f"Public key  : p = {P}, g = {G}, y = {Y}")
    print(f"Private key : x = {X}")
    if fixed_k is None:
        print("Nilai acak  : k berbeda untuk setiap huruf")
    else:
        print(f"Nilai acak  : k = {fixed_k}")

    print_line("PREPROCESSING PESAN")
    print(f"Pesan asli                         : {original_message}")
    print(f"Setelah uppercase dan hapus spasi  : {normalized_message}")
    print("Konversi                           : A=0, B=1, ..., Z=25")

    print_line("RUMUS ENKRIPSI ELGAMAL")
    print("a = g^k mod p")
    print("b = (y^k * m) mod p")
    print("ciphertext = (a, b)")

    print_line("PERHITUNGAN UTAMA")
    if fixed_k is None:
        print("Karena k berbeda untuk setiap huruf, nilai a dan y^k mod p juga berbeda.")
        print("Detail perhitungan ditampilkan pada tabel di bawah.")
    elif details:
        first = details[0]
        print(f"a = {G}^{fixed_k} mod {P} = {first['a']}")
        print(f"y^k mod p = {Y}^{fixed_k} mod {P} = {first['multiplier']}")
        print(f"Jadi b = ({first['multiplier']} * m) mod {P}")

    print_line("TABEL ENKRIPSI")
    print(f"{'No':>2} | {'Huruf':^5} | {'m':>2} | {'k':>4} | {'a':>4} | {'y^k mod p':>9} | {'b':>4} | {'Ciphertext (a,b)':<18}")
    print("-" * 92)
    for index, item in enumerate(details, start=1):
        ciphertext = f"({item['a']}, {item['b']})"
        print(
            f"{index:>2} | {item['char']:^5} | {item['m']:>2} | {item['k']:>4} | "
            f"{item['a']:>4} | {item['multiplier']:>9} | {item['b']:>4} | {ciphertext:<18}"
        )

    print_line("DAFTAR CIPHERTEXT")
    print([item["ciphertext"] for item in details])

    print_block_report(details)

def print_block_report(details):
    print_line("VERSI TULISAN PER BLOK")
    for block_index, start in enumerate(range(0, len(details), 2), start=1):
        block_items = details[start:start + 2]
        block_text = "".join(item["char"] for item in block_items)
        print(f"\nBlok {block_index}: huruf {block_text}")

        for item in block_items:
            print(f"\nHuruf {item['char']}:")
            print(f"m = {item['char']} = {item['m']}, k = {item['k']}")
            print(f"a = {G}^{item['k']} mod {P} = {item['a']}")
            print(f"y^k mod p = {Y}^{item['k']} mod {P} = {item['multiplier']}")
            print(f"b = ({item['multiplier']} * {item['m']}) mod {P} = {item['b']}")
            print(f"Ciphertext = ({item['a']}, {item['b']})")

def print_decryption_report(details):
    plaintext = "".join(item["char"] for item in details)

    print_line("DATA KUNCI")
    print(f"Private key : x = {X}")
    print(f"Modulus     : p = {P}")

    print_line("RUMUS DEKRIPSI ELGAMAL")
    print("ciphertext = (a, b)")
    print("s = a^x mod p")
    print("s_inverse = s^(-1) mod p")
    print("m = (b * s_inverse) mod p")
    print("Konversi hasil: A=0, B=1, ..., Z=25")

    print_line("HASIL DEKRIPSI")
    print(f"Plaintext angka : {[item['m'] for item in details]}")
    print(f"Plaintext huruf : {plaintext}")

    print_line("VERSI TULISAN DEKRIPSI PER BLOK")
    for block_index, start in enumerate(range(0, len(details), 2), start=1):
        block_items = details[start:start + 2]
        block_text = "".join(item["char"] for item in block_items)
        print(f"\nBlok {block_index}: hasil huruf {block_text}")

        for item in block_items:
            print(f"\nCiphertext {item['ciphertext']}:")
            print(f"a = {item['a']}, b = {item['b']}, x = {X}, p = {P}")
            print(f"s = {item['a']}^{X} mod {P} = {item['shared_secret']}")
            print(f"s_inverse = {item['shared_secret']}^(-1) mod {P} = {item['shared_secret_inverse']}")
            print(f"m = ({item['b']} * {item['shared_secret_inverse']}) mod {P} = {item['m']}")
            print(f"Huruf = {item['m']} = {item['char']}")

def read_cipher_pair():
    c1 = int(input("Masukkan c1/a: "))
    c2 = int(input("Masukkan c2/b: "))
    return c1, c2

def main():
    print("ElGamal Encryption and Decryption")
    print(f"Public key  : p={P}, g={G}, y={Y}")
    print(f"Private key : x={X}, p={P}\n")
    print("Pilih menu:")
    print("1. Enkripsi angka")
    print("2. Dekripsi angka")
    print("3. Enkripsi teks UTF-8")
    print("4. Dekripsi teks UTF-8")
    print("5. Enkripsi teks sesuai tabel A=0, ..., Z=25")
    print("6. Dekripsi teks sesuai tabel A=0, ..., Z=25")
    print()

    choice = input("Pilihan: ").strip()

    if choice == "1":
        m = int(input(f"Masukkan angka m (0 sampai {P - 1}): "))
        k_input = input("Masukkan k atau kosongkan untuk acak: ").strip()
        k = int(k_input) if k_input else None
        c1, c2 = encrypt_number(m, k)
        print("\nCiphertext:")
        print(f"a/c1 = {c1}")
        print(f"b/c2 = {c2}")

    elif choice == "2":
        pair = read_cipher_pair()
        m = decrypt_number(pair)
        print("\nPlaintext angka:")
        print(m)

    elif choice == "3":
        message = input("Masukkan pesan teks: ")
        encrypted = encrypt_message(message)
        print("\nCiphertext teks:")
        print(encrypted)

    elif choice == "4":
        raw_ciphertext = input("Masukkan ciphertext teks, contoh [(1, 2), (3, 4)]: ")
        ciphertext = ast.literal_eval(raw_ciphertext)
        decrypted = decrypt_message(ciphertext)
        print("\nPlaintext teks:")
        print(decrypted)

    elif choice == "5":
        message = input("Masukkan pesan teks A-Z: ")
        k_input = input("Masukkan k tetap atau kosongkan supaya k acak per huruf: ").strip()
        fixed_k = int(k_input) if k_input else None
        normalized_message = normalize_table_message(message)
        details = encrypt_table_message_details(message, fixed_k)
        print_encryption_report(message, normalized_message, details, fixed_k)

    elif choice == "6":
        raw_ciphertext = input("Masukkan ciphertext, contoh [(812, 3), (812, 51)]: ")
        ciphertext = ast.literal_eval(raw_ciphertext)
        details = decrypt_table_message_details(ciphertext)
        print_decryption_report(details)

    else:
        print("Pilihan tidak valid.")

if __name__ == "__main__":
    main()
