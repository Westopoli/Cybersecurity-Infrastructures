#!/bin/bash

# Ensure script exits on error
set -e

# Create directories
mkdir -p alice
mkdir -p bob

# Compile Alice and Bob
gcc alice_ecdh.c -lssl -lcrypto -o alice_ecdh
gcc bob_ecdh.c -lssl -lcrypto -o bob_ecdh


# Run Alice and Bob
echo "Running Alice..."
./alice_ecdh alice/alice_seed.txt

echo "Running Bob..."
./bob_ecdh bob/bob_seed.txt

echo "Running Alice..."
./alice_ecdh alice/alice_seed.txt

# Optionally, verify that both computed secrets match
ALICE_SECRET=$(cat alice/secret_hex.txt)
BOB_SECRET=$(cat bob/secret_hex.txt)

if [ "$ALICE_SECRET" = "$BOB_SECRET" ]; then
    echo "Success: Shared secrets match!"
else
    echo "Warning: Shared secrets do NOT match!"
fi
