# ElGamal Encryption, Decryption, and Digital Signature
This project implements a simple ElGamal encryption/decryption and ElGamal digital signature program for a cryptography assignment. The program can show the process step by step, so the result can be copied into a written report.

## Key Data
The program uses these values:
```text
p = 1009   (prime modulus)
g = 11     (generator)
x = 123    (private key)
y = g^x mod p = 510   (public key)
```

## Message Preprocessing
For the A-Z text mode, the message is processed before encryption/signing:
1. Convert all letters to uppercase.
2. Remove all spaces.
3. Convert letters into numbers:
```text
A = 0, B = 1, C = 2, ..., Z = 25
```
Example:
```text
Original message : bri gida
Processed message: BRIGIDA
```

---

## Part 1 — ElGamal Encryption / Decryption

### Encryption Formula
For each message value `m`, choose a random value `k`.
```text
a = g^k mod p
b = (y^k * m) mod p
ciphertext = (a, b)
```
If `k = 50`, then:
```text
a = 11^50 mod 1009 = 812
y^k mod p = 510^50 mod 1009 = 3
```
For letter `B`:
```text
B = 1
b = (3 * 1) mod 1009 = 3
ciphertext = (812, 3)
```

### Decryption Formula
For each ciphertext pair `(a, b)`, use the private key `x`.
```text
s = a^x mod p
s_inverse = s^(-1) mod p
m = (b * s_inverse) mod p
```
Example with ciphertext `(812, 3)`:
```text
s = 812^123 mod 1009 = 3
s_inverse = 3^(-1) mod 1009 = 673
m = (3 * 673) mod 1009 = 1
1 = B
```

---

## Part 2 — ElGamal Digital Signature

Digital signature proves that a message was really sent by the owner of the private key `x`, and that the message was not changed. Unlike encryption/decryption, the private key `x` is used to **sign**, and the public key `y` is used to **verify**.

Since `p - 1 = 1008`, the random value `k` used for signing must satisfy:
```text
gcd(k, p - 1) = 1
```
(`k` must be coprime with `p - 1`, not just any random number like in encryption.)

### Signing Formula
For a message value `m` (or a message hash), choose `k` such that `gcd(k, p-1) = 1`.
```text
r = g^k mod p
k_inverse = k^(-1) mod (p - 1)
s = (m - x*r) * k_inverse mod (p - 1)
signature = (r, s)
```

Example with `m = 26` and `k = 25`:
```text
r = 11^25 mod 1009 = 776
k_inverse = 25^(-1) mod 1008 = 121
s = (26 - 123*776) * 121 mod 1008 = 578
Signature = (r, s) = (776, 578)
```

### Verification Formula
Using the public key `y`, check whether the signature is valid:
```text
v1 = (y^r * r^s) mod p
v2 = g^m mod p
valid if v1 == v2
```
Example with signature `(776, 578)` for `m = 26`:
```text
v1 = (510^776 * 776^578) mod 1009 = 464
v2 = 11^26 mod 1009 = 464
v1 == v2 -> Valid signature
```

### Signing Text (A-Z mode)
Since a digital signature is normally computed once per message (not per letter like encryption), the A-Z text mode signs a single **hash value** derived from the whole message:
```text
hash = (sum of all letter values) mod (p - 1)
```
Example for message `BRI`:
```text
B = 1, R = 17, I = 8
hash = (1 + 17 + 8) mod 1008 = 26
```
This hash is then signed using the formula above, producing one signature `(r, s)` for the entire message — not one per letter.

> Note: this hash is a simple additive sum used only so the calculation can be done by hand for the assignment. It is **not** a cryptographically secure hash function (e.g. SHA-256) — real-world ElGamal signatures should hash the message with a proper cryptographic hash function before signing.

---

## How to Run
Run the program with Python:
```bash
python3 el_gamal.py
```
Then choose one of the menu options:
```text
1. Encrypt a number
2. Decrypt a number
3. Encrypt UTF-8 text
4. Decrypt UTF-8 text
5. Encrypt text using A=0, ..., Z=25
6. Decrypt text using A=0, ..., Z=25
7. Sign a number (Digital Signature)
8. Verify a number signature
9. Sign text using A=0, ..., Z=25 (Digital Signature)
10. Verify text signature (A=0, ..., Z=25)
```

## Recommended Mode for the Assignment
Use option `5` to encrypt a message using the A-Z conversion.
If you want the same result as the fixed calculation example, enter:
```text
k = 50
```
If you leave `k` blank, the program will choose a different random `k` for each letter. This makes the value of `a` different for each letter.
Use option `6` to decrypt a ciphertext list such as:
```text
[(812, 3), (812, 51), (812, 24)]
```

For digital signature, use option `9` to sign a message using the A-Z hash.
If you want the same result as the fixed calculation example, enter:
```text
k = 25
```
Use option `10` to verify a signature — you'll be asked for the original message plus `r` and `s`.

## Example Output — Encryption
For message:
```text
BRI
```
with:
```text
k = 50
```
the ciphertext is:
```text
[(812, 3), (812, 51), (812, 24)]
```
The program also prints a written block format, for example:
```text
Block 1: letter B
m = 1, k = 50
a = 11^50 mod 1009 = 812
y^k mod p = 510^50 mod 1009 = 3
b = (3 * 1) mod 1009 = 3
Ciphertext = (812, 3)
```
This format is useful for rewriting the calculation by hand.

## Example Output — Digital Signature
For message:
```text
BRI
```
with:
```text
k = 25
```
the program prints:
```text
Processed message: BRI
Letter values    : [1, 17, 8]
Hash (sum of letter values mod p-1) = 26 mod 1008 = 26

m = 26, k = 25   (k must be coprime with p-1 = 1008)
r = 11^25 mod 1009 = 776
k_inverse = 25^(-1) mod 1008 = 121
s = (m - x*r) * k_inverse mod 1008
s = (26 - 123*776) * 121 mod 1008 = 578
Signature = (r, s) = (776, 578)
```
Verifying with the same message and signature prints:
```text
v1 = (y^r * r^s) mod p = (510^776 * 776^578) mod 1009 = 464
v2 = g^m mod p = 11^26 mod 1009 = 464
Valid signature: True
```

## Notes
This implementation is designed for learning and assignment demonstration. In real cryptographic systems, ElGamal must use large secure parameters, a fresh random `k` for each encryption/signature, and a proper cryptographic hash function (e.g. SHA-256) for signing — not the simple additive hash used here.
