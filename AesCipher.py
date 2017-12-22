import binascii

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]


class ECB:

    def __init__(self):
        self.mode = AES.MODE_ECB

    def encrypt(self, raw):
        key = Random.new().read(BS)
        raw = pad(raw)
        cipher = AES.new(key, self.mode)
        key_hex = binascii.hexlify(key)
        message_hex = binascii.hexlify(cipher.encrypt(raw))
        print "--------------------------------------------------------------------------------------------------------"
        print "ECB_ENCRYPT - Wygenerowany klucz (HEX): " + key_hex
        print "ECB_ENCRYPT - Zaszyfrowana wiadomosc (HEX): " + message_hex
        print "ECB_ENCRYPT - Odszyfrowana wiadomosc: " + self.decrypt(key_hex, message_hex)
        print "--------------------------------------------------------------------------------------------------------"

    def decrypt(self, key, message):
        cipher = AES.new(key.decode('hex'), self.mode)
        return cipher.decrypt(message.decode('hex'))


class CBC:

    def __init__(self):
        self.mode = AES.MODE_CBC

    def encrypt(self, raw):
        key = Random.new().read(BS)
        initial_vector = Random.new().read(BS)
        raw = pad(raw)
        cipher = AES.new(key, self.mode, initial_vector)
        key_hex = binascii.hexlify(key)
        initial_vector_hex = binascii.hexlify(initial_vector)
        message_hex = binascii.hexlify(cipher.encrypt(raw))
        print "--------------------------------------------------------------------------------------------------------"
        print "CBC_ENCRYPT - Wygenerowany klucz (HEX): " + key_hex
        print "CBC_ENCRYPT - Wygenerowany wektor (HEX): " + initial_vector_hex
        print "CBC_ENCRYPT - Zaszyfrowana wiadomosc (HEX): " + message_hex
        print "CBC_ENCRYPT - Odszyfrowana wiadomosc: " + self.decrypt(key_hex, initial_vector_hex, message_hex)
        print "--------------------------------------------------------------------------------------------------------"

    def decrypt(self, key, initial_vector, message):
        cipher = AES.new(key.decode('hex'), self.mode, initial_vector.decode('hex'))
        return unpad(cipher.decrypt(message.decode('hex')))


class CTR:

    def __init__(self,):
        self.mode = AES.MODE_CTR

    def encrypt(self, raw):
        key = Random.new().read(BS)
        initial_vector = Random.new().read(BS)
        raw = pad(raw)
        counter = Counter.new(128, initial_value=long(binascii.hexlify(initial_vector), BS))
        cipher = AES.new(key, self.mode, counter=counter)
        key_hex = binascii.hexlify(key)
        initial_vector_hex = binascii.hexlify(initial_vector)
        message_hex = binascii.hexlify(cipher.encrypt(raw))
        print "--------------------------------------------------------------------------------------------------------"
        print "CTR_ENCRYPT - Wygenerowany klucz (HEX): " + key_hex
        print "CTR_ENCRYPT - Wygenerowany wektor (HEX): " + initial_vector_hex
        print "CTR_ENCRYPT - Zaszyfrowana wiadomosc (HEX): " + message_hex
        print "CTR_ENCRYPT - Odszyfrowana wiadomosc: " + self.decrypt(key_hex, initial_vector_hex, message_hex)
        print "--------------------------------------------------------------------------------------------------------"

    def decrypt(self, key, initial_vector, message):
        counter = Counter.new(128, initial_value=long(initial_vector, BS))
        decoder = AES.new(key.decode('hex'), self.mode, counter=counter)
        return decoder.decrypt(message.decode('hex'))
