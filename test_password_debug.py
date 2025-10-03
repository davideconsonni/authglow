#!/usr/bin/env python
"""Debug password verification."""
import hashlib
from authglow.services.password import verify_password, hash_password

password = 'Admin123!'

# Test hash generation
new_hash = hash_password(password)
print('New hash:', new_hash)

# Test with stored hash
stored_hash = "$2b$12$fKdsoMyD0DVVa0V2c90QHeqFm4IHFLTcNlADRMVcKzhzijqp8iqzW"

# What we're actually comparing
password_sha = hashlib.sha256(password.encode('utf-8')).hexdigest()
print('SHA256 of password:', password_sha)

result = verify_password(password, stored_hash)
print('Verification result:', result)

# Let's also check if the new hash would work
result2 = verify_password(password, new_hash)
print('New hash verification:', result2)
