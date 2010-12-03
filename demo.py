"""
Demonstration the pythonaes package. 

The method for creating the key and iv from a password is something that I made up, not an industry standard.
    There are 256 bits of salt pulled from OS's cryptographically strong random source.
    Any specific password will generate minimally 2^128 different Keys.
    Any specific password will generate minimally 2^128 different IVs independent of Key

This method has not been tested rigourously, so you should not use this in a production system without
review by someone with a PhD. 

On decryption, salt is read from first 32 bytes of encrypted file.

Copyright (c) 2010, Adam Newman http://www.caller9.com/
Licensed under the MIT license http://www.opensource.org/licenses/mit-license.php
"""
__author__ = "Adam Newman"

import os
import hashlib
from aespython import key_expander, aes_cipher, cbc_mode

class AESdemo:
    def __init__(self):
        self._salt = None
        self._iv = None
        self._key = None
    
    def new_salt(self):
        self._salt = os.urandom(32)
    
    def set_iv(self, iv):
        self._iv = iv
    
    def set_key(self, key):
        self._key = key
        
    def create_key_from_password(self, password):
        if self._salt is None:
            return
        sha512 = hashlib.sha512(password.encode('utf-8') + self._salt[:16]).digest()
        self._key = bytearray(sha512[:32])
        self._iv = [i ^ j for i, j in zip(self._salt[16:], sha512[32:48])]
    
    def decrypt_file(self, in_file_path, out_file_path, password = None):
        
        with open(in_file_path, 'rb') as in_file:
            if password is not None:
                self._salt = in_file.read (32)
                self.create_key_from_password (password)
            
            if self._key is None or self._iv is None:
                return
            
            key_expander_256 = key_expander.KeyExpander(256)
            expanded_key = key_expander_256.expand(self._key)
            aes_cipher_256 = aes_cipher.AESCipher(expanded_key)
            aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
            aes_cbc_256.set_iv(self._iv)
            
            with open(out_file_path, 'wb') as out_file:
                eof = False
                while not eof:
                    in_data = in_file.read(16)
                    if (len(in_data) == 0):
                        eof = True
                    else:
                        out_data = aes_cbc_256.decrypt_block(in_data)
                        out_file.write(bytes(out_data))
                    
        
        self._salt = None
        
    def encrypt_file(self, in_file_path, out_file_path, password = None):
        if password is not None:
            self.new_salt()
            self.create_key_from_password(password)
        else:
            self._salt = None
        
        if self._key is None or self._iv is None:
            return
        
        key_expander_256 = key_expander.KeyExpander(256)
        expanded_key = key_expander_256.expand(self._key)
        aes_cipher_256 = aes_cipher.AESCipher(expanded_key)
        aes_cbc_256 = cbc_mode.CBCMode(aes_cipher_256, 16)
        aes_cbc_256.set_iv(self._iv)
        
        with open(in_file_path, 'rb') as in_file:
            with open(out_file_path, 'wb') as out_file:
                if self._salt is not None:
                    out_file.write(self._salt)
                
                eof = False
                while not eof:
                    in_data = in_file.read(16)
                    if (len(in_data) == 0):
                        eof = True
                    else:
                        out_data = aes_cbc_256.encrypt_block(in_data)
                        out_file.write(bytes(out_data))
                
        self._salt = None
        
if __name__ == "__main__":
    demo = AESdemo()    
    demo.encrypt_file('stuff.txt', 'out.crypt', 'foo')
    demo.decrypt_file('out.crypt', 'stuff2.txt', 'foo')