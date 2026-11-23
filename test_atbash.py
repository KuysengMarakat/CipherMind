
from classical.atbash import atbash_transform


# Test 1
encrypted = "SVOOL DLIOW"

result = atbash_transform(encrypted)

print("Encrypted:", encrypted)
print("Decrypted:", result)


# Test 2
encrypted = "GSRH RH Z HVXIVG"

result = atbash_transform(encrypted)

print("\nEncrypted:", encrypted)
print("Decrypted:", result)


# Test 3: Check that applying Atbash twice
# returns the original message

original = "HELLO WORLD"

first = atbash_transform(original)

second = atbash_transform(first)

print("\nOriginal:", original)
print("After two transformations:", second)


assert result == "THIS IS A SECRET"
assert atbash_transform("SVOOL DLIOW") == "HELLO WORLD"
assert second == original

print("\nALL ATBASH TESTS PASSED")
