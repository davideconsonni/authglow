import pyotp

# Test TOTP verification with various inputs
secret = 'JBSWY3DPEHPK3PXP'
totp = pyotp.TOTP(secret)
code = totp.now()
print('Current code:', code)

# Test various formats
test_codes = [
    '123456',  # 6 digits
    '123456 ',  # with trailing space
    ' 123456',  # with leading space
    '1234567',  # 7 digits
    '12345',    # 5 digits
    'ABCD-1234',  # backup code format
]

for c in test_codes:
    result = pyotp.TOTP('JBSWY3DPEHPK3PXP').verify(c, valid_window=1)
    print(f'Code: "{c}" -> {result}')

# Also test current code
print(f'\nCurrent valid code: {totp.now()}')
print(f'Verify current: {totp.verify(totp.now(), valid_window=1)}')