import os
import sys
import json
from pathlib import Path

# Add app to path so we can import key_providers
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.key_providers import AwsKmsProvider, KeyProviderError, KeyResolver
from app.config import settings

def run_smoke_test():
    print("--- EraseKey AWS KMS Smoke Test ---")
    
    mode = os.getenv("ERASEKEY_KMS_MODE")
    if mode != "aws":
        print(f"FAILED: ERASEKEY_KMS_MODE is '{mode}', expected 'aws'.")
        sys.exit(1)
        
    key_id = os.getenv("ERASEKEY_AWS_KMS_KEY_ID")
    if not key_id:
        print("FAILED: ERASEKEY_AWS_KMS_KEY_ID is not set.")
        sys.exit(1)
        
    print(f"Target Key ID: ...{key_id[-4:] if len(key_id) > 4 else key_id}")
    
    try:
        provider = AwsKmsProvider(key_id=key_id)
        context = {"app": "erasekey", "test": "smoke-test", "purpose": "verification"}
        
        print("1. Testing GenerateDataKey...")
        plaintext, ciphertext = provider.generate_data_key(context)
        print("   SUCCESS: Generated data key.")
        
        print("2. Testing Decrypt (Correct Context)...")
        unwrapped = provider.unwrap_data_key(ciphertext, context)
        if unwrapped != plaintext:
            print("   FAILED: Decrypted plaintext does not match original.")
            sys.exit(1)
        print("   SUCCESS: Decrypted data key.")
        
        print("3. Testing Decrypt (Mismatch Context)...")
        bad_context = {"app": "erasekey", "test": "smoke-test", "purpose": "failure-test"}
        try:
            provider.unwrap_data_key(ciphertext, bad_context)
            print("   FAILED: Decrypt succeeded with wrong context (security risk!)")
            sys.exit(1)
        except KeyProviderError:
            print("   SUCCESS: Decrypt failed as expected with mismatched context.")
            
        print("\n--- SMOKE TEST PASSED ---")
        
    except Exception as e:
        print(f"\nFAILED: Unexpected error during smoke test: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_smoke_test()
