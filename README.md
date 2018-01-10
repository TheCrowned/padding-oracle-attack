# padding-oracle-attack
A padding oracle attack on AES-128 made with Python.

In symmetric cryptography, the padding oracle attack can be applied to the CBC mode of operation, where the "oracle" (usually a server) leaks data about whether the padding of an encrypted message is correct or not. Such data can allow attackers to decrypt (and sometimes encrypt) messages through the oracle using the oracle's key, without knowing the encryption key.

## How to use 
Run attack.py.

Look at test_the_attack() in attack.py to define your own messages. 
