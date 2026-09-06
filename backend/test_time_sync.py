import pyotp
import time

# Test TOTP verification with time offsets
secret = 'JBSWY3DPEHPK3PXP'
totp = pyotp.TOTP(secret)
current_code = totp.now()
print(f'Current code: {current_code}')

# Test verification with current time
print(f'Verify current: {pyotp.TOTP(secret).verify(current_code, valid_window=1)}')

# Test with time offsets
for i in range(-2, 3):
    test_time = int(time.time()) + (i * 30)
    code = totp.at(test_time)
    valid = pyotp.TOTP(secret).verify(code, valid_window=1)
    print(f'Offset {i}: code={code}, valid={valid}')

# Test with current code
print(f'Current valid: {pyotp.TOTP(secret).verify(current_code, valid_window=1)}')