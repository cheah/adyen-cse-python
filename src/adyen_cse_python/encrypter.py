from datetime import datetime
from builtins import bytes
from builtins import object
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from os import urandom
import pytz
import json
import base64


class ClientSideEncrypter(object):
    def __init__(self, adyen_public_key):
        self.adyen_public_key = adyen_public_key

    def generate_adyen_nonce(self, name, pan, cvc, expiry_month, expiry_year):
        """
        Generate Adyen Nonce from the provided card data.

        Adyen Nonce Format:

        "adyenan" + "0_1_1" + "$" + "Base64-Encoded encrypted_aes_key" + "$" + "Base64-Encoded encrypted_card_component"
        """

        plain_card_data = self.generate_card_data_json(name, pan, cvc, expiry_month, expiry_year)
        card_data_json_string = json.dumps(plain_card_data, sort_keys=True)

        # Encrypt the actual card data with symmetric encryption
        aes_key = self._generate_aes_key()
        nonce = self._generate_nonce()
        encrypted_card_data = self._encrypt_with_aes_key(aes_key, nonce, bytes(card_data_json_string, encoding='utf-8'))
        encrypted_card_component = nonce + encrypted_card_data

        # Encrypt the AES Key with asymmetric encryption
        public_key = self.decode_adyen_public_key(self.adyen_public_key)
        encrypted_aes_key = self._encrypt_with_public_key(public_key, aes_key)

        return "{}{}${}${}".format("adyenan",
                                   "0_1_1",
                                   base64.standard_b64encode(encrypted_aes_key).decode(),
                                   base64.standard_b64encode(encrypted_card_component).decode())

    @staticmethod
    def generate_card_data_json(name, pan, cvc, expiry_month, expiry_year):
        generation_time = datetime.now(tz=pytz.timezone('UTC')).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        return {
            "holderName": name,
            "number": pan,
            "cvc": cvc,
            "expiryMonth": expiry_month,
            "expiryYear": expiry_year,
            "generationtime": generation_time
        }

    @staticmethod
    def decode_adyen_public_key(encoded_public_key):
        backend = default_backend()
        key_components = encoded_public_key.split("|")
        public_number = rsa.RSAPublicNumbers(int(key_components[0], 16), int(key_components[1], 16))
        return backend.load_rsa_public_numbers(public_number)

    @staticmethod
    def _encrypt_with_public_key(public_key, plaintext):
        ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
        return ciphertext

    @staticmethod
    def _generate_aes_key():
        return AESCCM.generate_key(256)

    @staticmethod
    def _encrypt_with_aes_key(aes_key, nonce, plaintext):
        cipher = AESCCM(aes_key, tag_length=8)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return ciphertext

    @staticmethod
    def _generate_nonce():
        return urandom(12)
