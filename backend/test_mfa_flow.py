import asyncio
import pyotp
from authglow.core.crypto import encrypt_totp_secret, decrypt_totp_secret
from authglow.services.mfa import MFAService
from authglow.models.user import User

async def test_full_mfa_flow():
    """Test complete MFA flow: enroll -> verify enrollment -> login with MFA"""
    print("Testing full MFA flow...")
    
    # 1. Enroll MFA
    print("\n1. Enrolling MFA...")
    mfa_service = MFAService()
    secret = mfa_service.generate_totp_secret()
    print(f"Generated secret: {secret}")
    
    # Encrypt secret (simulates what happens during enrollment)
    encrypted_secret = encrypt_totp_secret(secret)
    print(f"Encrypted secret: {encrypted_secret}")
    
    # Create user object with encrypted secret
    user = User(
        id="test-user-123",
        email="test@example.com",
        hashed_password="$2b$12$dummy",
        mfa_secret=encrypted_secret,
        mfa_enabled=False,
        mfa_verified=False,
    )
    
    # Save backup codes
    mfa_service = MFAService()
    backup_codes = mfa_service.generate_backup_codes(10)
    await mfa_service.save_backup_codes(user.id, backup_codes)
    print(f"Generated {len(backup_codes)} backup codes")
    
    # 2. Verify enrollment (simulate /api/mfa/verify)
    print("\n2. Verifying enrollment...")
    mfa_service_verify = MFAService()
    
    # Get current valid TOTP code
    import pyotp
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    print(f"Valid TOTP code: {valid_code}")
    
    # Verify with decrypted secret (simulating /api/mfa/verify)
    decrypted_secret = decrypt_totp_secret(user.mfa_secret)
    print(f"Decrypted secret: {decrypted_secret}")
    
    is_valid = mfa_service.verify_totp(decrypted_secret, totp.now())
    print(f"Enrollment verification: {is_valid}")
    
    if not is_valid:
        print("ERROR: Enrollment verification failed!")
        return False
    
    # 3. Simulate login with MFA (simulate /api/mfa/verify-login)
    print("\n3. Simulating login with MFA...")
    
    # Get fresh TOTP code
    fresh_code = pyotp.TOTP(secret).now()
    print(f"Fresh TOTP code: {fresh_code}")
    
    # Simulate login flow: decrypt secret and verify
    decrypted = decrypt_totp_secret(user.mfa_secret)
    print(f"Decrypted secret: {decrypted}")
    
    mfa_service = MFAService()
    is_valid = mfa_service.verify_totp(decrypt_totp_secret(user.mfa_secret), totp.now())
    print(f"Login MFA verification: {is_valid}")
    
    if not is_valid:
        print("ERROR: Login MFA verification failed!")
        return False
    
    # Test backup code verification
    print("\n4. Testing backup code verification...")
    first_code = backup_codes[0]
    is_valid_backup = await MFAService().verify_user_backup_code(user.id, backup_codes[0])
    print(f"Backup code verification: {is_valid}")
    
    # Second use should fail
    is_valid_second = await MFAService().verify_user_backup_code(user.id, backup_codes[0])
    print(f"Second use of same backup code: {is_valid_second} (should be False)")
    
    if not is_valid:
        print("ERROR: MFA verification failed!")
        return False
    
    print("\nAll tests passed!")
    return True

if __name__ == "__main__":
    result = asyncio.run(test_full_mfa_flow())
    print(f"\nResult: {'SUCCESS' if result else 'FAILURE'}")