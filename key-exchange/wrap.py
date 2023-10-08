#
# Wrap secret key with public key (RSA)
# ECC not currently supported
#
# Requires python3.6+
# Modules: cryptography
#
# Public key must in DER/SPKI format

from ecies import *
# from cryptography.hazmat.backends import default_backend       


if len(sys.argv) != 5:
    print("wrap.py <ecc|rsa> <public_key_file> <secret_file> <wrapped_file>");
    sys.exit(0)

with open(sys.argv[2], 'rb') as f:
    public = f.read()

with open(sys.argv[3], 'rb') as f:
    secret = f.read()

# Public key encrypt AES-256 key
key = os.urandom(32)
publicKey = serialization.load_der_public_key(public)

if sys.argv[1] == 'rsa':
    wrapped = publicKey.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
elif sys.argv[1] == 'ecc':
    wrapped = ecies_encrypt(publicKey, key)
else:
    raise TypeError("Incorrect encryption algorithm")

 # AES-256 wrap secret key
padding = 8 - (len(secret) % 8)
padded = secret + padding.to_bytes(padding, 'big')
ciphertext = keywrap.aes_key_wrap(key, padded)

# Format wrapped key
packed = struct.pack('!i%dsi%ds' % (len(wrapped), len(ciphertext)), len(wrapped), wrapped, len(ciphertext), ciphertext)
with open(sys.argv[4], 'wb') as f:
    f.write(packed)






