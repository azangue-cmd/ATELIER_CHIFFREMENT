"""
fernet_atelier1.py

Programme de chiffrement / déchiffrement de fichiers
à l'aide de la bibliothèque cryptography (Fernet).

IMPORTANT :
La clé Fernet n'est PAS générée dans le code.
Elle est récupérée depuis une variable d'environnement
(GitHub Repository Secret : FERNET_KEY).
"""

import sys  # Permet de récupérer les arguments passés en ligne de commande
import os   # Permet d'accéder aux variables d'environnement
from cryptography.fernet import Fernet, InvalidToken


def load_key():
    """
    Charge la clé Fernet depuis la variable d'environnement FERNET_KEY.

    Pourquoi ?
    Pour éviter de stocker la clé dans le code source.
    Cela empêche qu'elle soit committée dans Git.

    Retour :
        key (bytes) : clé encodée au format bytes (obligatoire pour Fernet)
    """

    # Récupération de la variable d'environnement
    key = os.environ.get("FERNET_KEY")

    # Vérification de la présence de la clé
    if not key:
        print("❌ FERNET_KEY non défini dans les variables d'environnement.")
        sys.exit(1)  # Arrêt du programme avec code d'erreur

    # Fernet attend une clé en bytes (et non en string)
    return key.encode()


def encrypt_file(input_file, output_file, fernet):
    """
    Chiffre le contenu d'un fichier.

    Paramètres :
        input_file (str)  : fichier à chiffrer
        output_file (str) : fichier de sortie chiffré
        fernet (Fernet)   : instance Fernet initialisée avec la clé
    """

    # Lecture du fichier en mode binaire (rb = read binary)
    # Important car on chiffre des bytes et non du texte
    with open(input_file, "rb") as f:
        data = f.read()

    # Chiffrement des données
    encrypted = fernet.encrypt(data)

    # Écriture du résultat chiffré dans le fichier de sortie
    with open(output_file, "wb") as f:
        f.write(encrypted)

    print(f"✅ Fichier chiffré avec succès : {output_file}")


def decrypt_file(input_file, output_file, fernet):
    """
    Déchiffre un fichier chiffré avec Fernet.

    Paramètres :
        input_file (str)  : fichier chiffré
        output_file (str) : fichier déchiffré
        fernet (Fernet)   : instance Fernet initialisée avec la clé
    """

    # Lecture du fichier chiffré en mode binaire
    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    try:
        # Tentative de déchiffrement
        decrypted = fernet.decrypt(encrypted_data)

    except InvalidToken:
        """
        Cette exception est levée si :
        - Le fichier a été modifié (HMAC invalide)
        - La clé est incorrecte
        - Le token est corrompu

        C'est une protection d'intégrité fournie par Fernet.
        """
        print("❌ Erreur : Token invalide (fichier modifié ou mauvaise clé).")
        sys.exit(1)

    # Écriture des données déchiffrées
    with open(output_file, "wb") as f:
        f.write(decrypted)

    print(f"✅ Fichier déchiffré avec succès : {output_file}")


def main():
    """
    Fonction principale du programme.

    Elle :
    1. Vérifie les arguments
    2. Charge la clé secrète
    3. Initialise Fernet
    4. Lance l'action demandée (encrypt/decrypt)
    """

    # Vérifie qu'on a exactement 3 arguments :
    # action + input + output
    if len(sys.argv) != 4:
        print("Usage :")
        print("  python app/fernet_atelier1.py encrypt <input> <output>")
        print("  python app/fernet_atelier1.py decrypt <input> <output>")
        sys.exit(1)

    # Récupération des arguments
    action = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    # Chargement sécurisé de la clé
    key = load_key()

    # Création de l'objet Fernet avec la clé secrète
    fernet = Fernet(key)

    # Sélection de l'action demandée
    if action == "encrypt":
        encrypt_file(input_file, output_file, fernet)

    elif action == "decrypt":
        decrypt_file(input_file, output_file, fernet)

    else:
        print("❌ Action invalide. Utilise 'encrypt' ou 'decrypt'.")
        sys.exit(1)


# Point d'entrée du programme
# Ce bloc s'exécute uniquement si le fichier est lancé directement
if __name__ == "__main__":
    main()