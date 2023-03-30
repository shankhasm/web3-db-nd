import base64
import unittest
import web3db
from base64 import b64decode, b64encode
from ecies.utils import generate_eth_key, generate_key
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

WEB3DB_HOST = 'https://sensorweb.us:8084'
RSA_KEYPAIR = RSA.generate(4096)
ECC_KEYPAIR = generate_key()

PEM_HEADER = '-----BEGIN PUBLIC KEY-----\n'
WEB3DB_RSA_PUBKEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA9TKu/hU6k3aSIeBSJorC681D7\
zybDr82QhSZxjbbh2G7T5908KrPsqKcym1yl1b+76nT3SPGGcwzAu5Uzj9gML/yprF42JwsJA+pTF8LouAepkxKj0R\
NyQnJLfQePmjmKUrHe04VL7uS3gR9nsOHDNfl6U7gQlBG4S3jJzv6NfcY2uZgPEuvotNlkhqNq3YFXl88B+2QpjyBx\
9B1ZggZt1fCfb85s8LK5j+PLqlB0AmWi8tHHnbXybdaUVGYio7slkcLvCUQLYo0T2petQ8dJn+GHRLGLiKi3nJCRdl\
M5oVnXHQI4DVPAz4kakPjXGCNvChytigN6wrFjdTvYEjjpL8jhyrAa6eHa3O3KRcKHIwFz/jjPFEZ9e8m7GaPOALsy\
4RNuEuUHwJOlz8asfm93qwCRoYTmi6ftd9piCOIrY+1Mt5nM5CTRnS2lmXZDibilJAQTtZ9WdorL1Cb5GF1yFdLn78\
zON1SCeZ51Xi32Y/XZ12bUPzlfL+sbSyCjgZensSvXqvwNwgVJcWzgkc/gHqlpcLjSWIFaSmvkcJgyDvpJHJrlSn4y\
9XfU/KSTt9APQd8d3yHXj/jvg7omGLKigl1E1ui2CWUlj85WPxqsMfaPO1JQ5Bz1V0blRtCFXin3wem6RWOYJPHiGm\
Ecc06O0piN5TsEnOYD0uu/7BfRIsCAwEAAQ=="
PEM_FOOTER = '\n-----END PUBLIC KEY-----'
WEB3DB_RSA_PUBKEY = PEM_HEADER + WEB3DB_RSA_PUBKEY + PEM_FOOTER

WEB3DB = web3db.Web3DB(
    host=WEB3DB_HOST, rsa_key_pair=RSA_KEYPAIR, ecc_key_pair=ECC_KEYPAIR)

class Web3DBTests(unittest.TestCase):

    # def test_aes_encryption(self):
    #     msg = "Howdy"
    #     key = get_random_bytes(32)
    #     ciphertext = web3db._encrypt_aes(key, msg.encode())
    #     self.assertEqual(web3db._decrypt_aes(key, ciphertext).decode(), msg)

    # def test_rsa_encryption(self):
    #     msg = "Hello"
    #     ciphertext = web3db._encrypt_rsa(RSA_KEYPAIR.publickey(), msg.encode())
    #     self.assertEqual(web3db._decrypt_rsa(
    #         RSA_KEYPAIR, ciphertext).decode(), msg)

    def test_format_storage_node_pubkey(self):
        pubkey = WEB3DB._call_web3db(
            WEB3DB.host + '/api/get_web3db_pubkey', web3db.HTTP.GET)
        pubkey = web3db._format_storage_node_pubkey(pubkey)
        try:
            RSA.importKey(pubkey)
        except:
            self.fail()
        self.assertEqual(pubkey, WEB3DB_RSA_PUBKEY)

    # def test_ecc_pub_key_to_string(self):
    #     web3db._ecc_pub_to_string(ECC_KEYPAIR)
    
    # def test_rsa_pub_key_to_string(self):
    #     web3db._rsa_pub_to_string(RSA_KEYPAIR)

    # def test_list_dbs(self):
    #     try:
    #         WEB3DB.list_dbs()
    #     except:
    #         self.fail()
    
    # def test_new_db(self):
    #     WEB3DB.new_db(name='testThread')
    #     print(WEB3DB.list_dbs())
    

    # def test_encrypt_identity(self):
    #     encrypted = web3db._encrypt_rsa(RSA.importKey(WEB3DB_RSA_PUBKEY), ECC_KEYPAIR.secret)
    #     encrypted = base64.b64encode(encrypted).decode('ascii')        


if __name__ == '__main__':
    unittest.main()
