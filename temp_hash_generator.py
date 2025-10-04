from authglow.services.password import hash_password

password = "password"
hashed = hash_password(password)
print(hashed)
