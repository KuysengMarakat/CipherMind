
from classical.caesar import (
    caesar_decrypt,
    brute_force_caesar
)


# Test 1: Known shift

print("TEST 1: Caesar Decryption")

result = caesar_decrypt("KHOOR ZRUOG", 3)

print("Encrypted:", "KHOOR ZRUOG")

print("Decrypted:", result)


# Test 2: Brute force

print("\nTEST 2: Brute Force")

candidates = brute_force_caesar("KHOOR ZRUOG")

for candidate in candidates:

    print(
        "Shift:",
        candidate["shift"],
        "| Result:",
        candidate["result"]
    )


print("\nCAESAR TEST COMPLETED")
