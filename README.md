# Purpose

- This java program can be used to encrypt files using password, AWS KMS and AWS KMS data key involving envelope encryption.

- The algorithm utilized in the password mode is AES with GCM mode

# File changes

- While utilizing Envelope encryption these are addition to data sizes

- Plaintext Size: 112 bytes
- Cipher Text Size: 128 bytes
- Encrypted data key Size: 168 bytes
- Total encrypted size: 296 bytes

- Note: The key size would remain constant with 168 bytes.

# Flow for envelope encryption (needed when file size is greater than 4kb)
1. Request Data key from AWS KMS
2. AWS returns both plain text and encrypted form of the data key.
3. Utilize the plain text version of the data key to encrypt the file utilizing AES 128 algo.
4. Discard the plain text version of the data key.
5. Write both encrypted data key and cipher text to a file.

# Flow for envelope decryption
1. Parse the file and read the encrypted data key
2. Send the encrypted data key to AWS KMS which will utilize the CMS (Customer managed key) to decrypt the data key.
3. Utilize the decrypted data key to decrypt the ciphertext.
4. Discard the decrypted data key after fetching the plaintext.

# Pro with envelope encryption and decryption:
1. The actual key never leaves AWS and is never prone to leakage from user error.
2. Data key is utilized to do the actual encryption and is discarded after usage.
3. Actual payload is never sent to AWS and is easier on the network and more secure.

# Con with envelope encryption and decryption:
1. 

# Flow for Normal KMS encryption (works only for file size less than 4kb)
1. Send an encryption request with the payload to AWS KMS with the key id.

# Flow for Normal KMS decryption
1. Send a decryption request with the ciphertext to AWS KMS with the key id.

# Pro with Normal KMS encryption and decryption:
1. The actual key never leaves AWS and is never prone to leakage from user error.

# Con with Normal KMS encryption and decryption
1. Payload needs to be send over the wire to KMS for actual crypto operations

# Ref
https://www.codeproject.com/Articles/5129195/AWS-Key-Management-System-KMS-to-Encrypt-and-Decry
