#
# Unwrap secret key with private key (RSA)
# ECC not currently supported
#
# Requires python3.6+
# Modules: cryptography
#
# Private key must be in DER/PKCS8 format

from ecies import *

if len(sys.argv) != 5:
    print("unwrap.py <ecc|rsa> <private_key_file> <wrapped_file> <secret_file>");
    sys.exit(0)

with open(sys.argv[2], 'rb') as f:
    private = f.read()

with open(sys.argv[3], 'rb') as f:
    packed = f.read()

# Unpack wrapped key
len1 = struct.unpack_from("!i", packed, 0)[0]
wrapped = struct.unpack_from("!%ds" % len1, packed, 4)[0]
len2 = struct.unpack_from("!i", packed, 4+len1)[0]
ciphertext = struct.unpack_from("!%ds" % len2, packed, 8+len1)[0]

# RSA decrypt AES key
privateKey = serialization.load_der_private_key(private, None)

if sys.argv[1] == 'rsa':
    key = privateKey.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
elif sys.argv[1] == 'ecc':
    key = ecies_decrypt(wrapped, privateKey)
else:
    raise TypeError("Incorrect encryption algorithm")

# AES unwrap secret and remove padding
padded = keywrap.aes_key_unwrap(key, ciphertext)
secret = padded[:len(padded)-padded[-1]]
with open(sys.argv[4], 'wb') as f:
    f.write(secret)

