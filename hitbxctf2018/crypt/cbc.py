from Crypto.Cipher import AES
from Crypto import Random
from hashlib import sha256
from signal import alarm
bs = 16


def pad(s):
    return s + (bs - len(s) % bs) * bytes((bs - len(s) % bs, ))


def unpad(s):
    return s[0:-s[-1]]


class cipher(object):
    def __init__(self, key):
        self.key = key

    def cbcPrimeEnc(self, key, iv, plain):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = pad(plain)
#       print(len(plain))
#       print(len(cipher.encrypt(plain)))
        return cipher.encrypt(plain)

    def cbcPrimeDec(self, key, iv, ciphertext):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(ciphertext)
        return unpad(plain)

    def encrypt(self, plaintext):
        hash = sha256(mac_key + plaintext).digest()
        iv = Random.new().read(bs)
#        print( iv)
        ciphertext = iv + \
            self.cbcPrimeEnc(authen_key, iv, hash) + \
            self.cbcPrimeEnc(self.key, iv, plaintext)
        return ciphertext.hex()

    def decrypt(self, ciphertext):
        cookie = bytes.fromhex(ciphertext)
        iv = cookie[:bs]
        mac = cookie[bs:4 * bs]
        ciphertext = cookie[4 * bs:]
        plaintext = self.cbcPrimeDec(self.key, iv, ciphertext)
        print(plaintext)
        hash = self.cbcPrimeDec(authen_key, iv, mac)
        print(hash.hex()[-63:])
        print(sha256(mac_key + plaintext).digest().hex()[-63:])
        if sha256(mac_key + plaintext).digest().hex()[-63:] == hash.hex()[-63:]:
            return str(plaintext, 'ISO-8859-1')
        else:
            # return high 136 bits hex string
            raise Exception(
                sha256(mac_key + plaintext).digest().hex()[-64:-30], hash.hex()[-64:-30])


encrypt_key = Random.new().read(bs)
mac_key = Random.new().read(2 * bs)
authen_key = Random.new().read(bs)
with open('flag', 'r') as fp:
    flag = fp.readline()
alarm(20)
while True:
    c = cipher(encrypt_key)
    print('welcome to Fantasy Terram')
    choice = input("Please [r]egister or [l]ogin :>>")
    if not choice:
        break
    if choice[0] == 'r':
        name = input('your name is:>>')
        name = bytes(name, 'ISO-8859-1') + b'user'
        if(len(name) > 1024):
            print("username too long!")
            break
        else:
            print("Here is your cookie:")
            print(c.encrypt(name))
    elif choice[0] == 'l':
        data = input('your cookie:>>')
        try:
            msg = c.decrypt(data)
            if msg[-4:] == 'user':
                print("Welcome %s!" % msg[:-4])
            elif msg[-5:] == 'admin':
                print(flag)
        except Exception as e:
            print('Wrong MAC! ')
            print(
                'the actual first 136 bits of sha256 and the suppposed first 136 bits is:>>' + str(e))
        else:
            exit()

    # must be delete!
    elif choice[0] == 'c':
        un = input('your username:>>')
        un = bytes(un, 'ISO-8859-1')
        print(sha256(mac_key + un).digest().hex())

    else:
        print("Unknown choice!")
        break
