import sys
import os
from nacl.secret import SecretBox
from nacl.utils import random
from nacl.exceptions import CryptoError


def load_key():
    """
    Charge la clé SECRETBOX_KEY depuis les variables d'environnement.
    La clé est stockée en hexadécimal.
    """

    key_hex = os.environ.get("SECRETBOX_KEY")

    if not key_hex:
        print("❌ SECRETBOX_KEY non défini.")
        sys.exit(1)

    return bytes.fromhex(key_hex)


def encrypt_file(input_file, output_file, box):
    """
    Chiffre un fichier avec SecretBox.
    """

    with open(input_file, "rb") as f:
        data = f.read()

    # Génération d'un nonce aléatoire (24 bytes)
    nonce = random(SecretBox.NONCE_SIZE)

    # Chiffrement
    encrypted = box.encrypt(data, nonce)

    # On stocke nonce + ciphertext dans le fichier
    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"✅ Fichier chiffré : {output_file}")


def decrypt_file(input_file, output_file, box):
    """
    Déchiffre un fichier SecretBox.
    """

    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted = box.decrypt(encrypted_data)

    except CryptoError:
        print("❌ Erreur : données corrompues ou mauvaise clé.")
        sys.exit(1)

    with open(output_file, "wb") as f:
        f.write(decrypted)

    print(f"✅ Fichier déchiffré : {output_file}")


def main():
    if len(sys.argv) != 4:
        print("Usage :")
        print("  python app/secretbox_crypto.py encrypt <input> <output>")
        print("  python app/secretbox_crypto.py decrypt <input> <output>")
        sys.exit(1)

    action = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    key = load_key()

    # Vérifie que la clé fait bien 32 bytes
    if len(key) != SecretBox.KEY_SIZE:
        print("❌ Clé invalide (32 bytes requis).")
        sys.exit(1)

    box = SecretBox(key)

    if action == "encrypt":
        encrypt_file(input_file, output_file, box)

    elif action == "decrypt":
        decrypt_file(input_file, output_file, box)

    else:
        print("❌ Action invalide (encrypt/decrypt).")
        sys.exit(1)


if __name__ == "__main__":
    main()