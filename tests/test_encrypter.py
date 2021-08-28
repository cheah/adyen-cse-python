import codecs

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from adyen_cse_python.encrypter import ClientSideEncrypter

PUB_EXPONENT = "10001"
MODULUS = "9201EBD5DC974FDE613A85AFF2728627FD2C227F18CF1C864FBBA3781908BB7BD72C818FC37D0B70EF8708705C623D" \
          "F4A9427A051B3C8205631716AAAC3FCB76114D91036E0CAEFA454254D135A1A197C1706A55171D26A2CC3E9371B86A725458" \
          "E82AB82C848AB03F4F0AF3127E7B2857C3B131D52B02F9A408F4635DA7121B5B4A53CEDE687D213F696D3116EB682A4CEFE6" \
          "EDFC54D25B7C57D345F990BB5D8D0C92033639FAC27AD232D9D474896668572F494065BC7747FF4B809FE3084A5E947F72E5" \
          "9309EDEAA5F2D81027429BF4827FB62006F763AFB2153C4A959E579390679FFD7ADE1DFE627955628DC6F2669A321626D699" \
          "A094FFF98243A7C105"


def test_generate_card_data_json():
    cse = ClientSideEncrypter(PUB_EXPONENT + "|" + MODULUS)
    json = cse.generate_card_data_json("Test Name", "4111111111111111", "737", "01", "2018")
    assert json['holderName'] == "Test Name"
    assert json['expiryYear'] == "2018"


def test_decode_adyen_public_key():
    cse = ClientSideEncrypter(PUB_EXPONENT + "|" + MODULUS)
    decoded_pub_key = cse.decode_adyen_public_key(PUB_EXPONENT + "|" + MODULUS)
    public_number = decoded_pub_key.public_numbers()

    assert decoded_pub_key.key_size == 2048
    assert public_number.e == int(PUB_EXPONENT, 16)
    assert public_number.n == int(MODULUS, 16)


def test_generate_adyen_nonce():
    cse = ClientSideEncrypter(PUB_EXPONENT + "|" + MODULUS)
    adyen_nonce = cse.generate_adyen_nonce("Test Name", "4111111111111111", "737", "08", "2018")
    assert adyen_nonce.startswith("adyenan0_1_1$")


# https://github.com/bcgit/bc-java/blob/master/prov/src/test/java/org/bouncycastle/jce/provider/test/AESTest.java
def test_java_bouncy_castle_ccm_matching():
    K = codecs.decode(b"404142434445464748494a4b4c4d4e4f", "hex")
    N = codecs.decode(b"10111213141516", "hex")
    P = codecs.decode(b"68656c6c6f20776f726c642121", "hex")
    C = codecs.decode(b"39264f148b54c456035de0a531c8344f46db12b388", "hex")

    cipher = AESCCM(K, tag_length=8)
    ciphertext = cipher.encrypt(N, P, None)

    assert ciphertext == C
