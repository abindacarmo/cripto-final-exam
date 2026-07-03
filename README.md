# ElGamal Encryption and Decryption

This project implements a simple ElGamal encryption and decryption program for a cryptography assignment. The program can show the encryption and decryption process step by step, so the result can be copied into a written report.

## Key Data

The program uses these values:
```

## Message Preprocessing

For the A-Z text mode, the message is processed before encryption:

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

## ElGamal Encryption Formula

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

## ElGamal Decryption Formula

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

## Example Output

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
Block 1: letters BR

Letter B:
m = B = 1, k = 50
a = 11^50 mod 1009 = 812
y^k mod p = 510^50 mod 1009 = 3
b = (3 * 1) mod 1009 = 3
Ciphertext = (812, 3)
```

This format is useful for rewriting the calculation by hand.

## Notes

This implementation is designed for learning and assignment demonstration. In real cryptographic systems, ElGamal must use large secure parameters and a fresh random `k` for each encryption.
