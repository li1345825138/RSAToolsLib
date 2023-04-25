# Simple RSA encrypt/decrypt library
***
 - This library is just wrap around standard RSA algorithm from java standard library to make easy to use.

# Usage
***
 - Before start to encrypt/decrypt message, you need to use <font color=Blue>RSAKeyGenerator</font> class to generate both private and public key file.
 - Class <font color=Blue>RSAKeyGenerator</font>:
   - This class is use for generate private and public key files
   - Con-structor argument: key length
     - Method:
       - generateKeyPair: this will generate both key file on your given location, please pass \<path>\privateKeyname.key and \<path>\publicKeyname.key as arguments.
 - Class <font color=Blue>RSAEncrypter</font>:
   - After you have both private and public key files, you could now use this class to encrypt you message.
   - You could choose neither private key or public key as your encrypt key. (If you don't know what is mean, please learn what is RSA encrypt first)
   - Con-structure arguments: the location of your encrypt key file is and which type of key is this key file
     - Method:
       - encryptContent(String): Encrypt given string content by using private key, return base64 encoded encrypted content
       - encryptContent(byte[]): Encrypt any original byte array content into encrypted byte array by using private key
 - Class <font color=Blue>RSADecrypter</font>:
   - This is pair of <font color=Blue>RSAEncrypter</font>, use for decrypt <font color=Blue>RSAEncrypter</font> encrypt content by provide decrypt key file.
   - Con-structure arguments: the location of your decrypt key file is which type of key is this key file
     - Method:
       - decryptContent(String): Decrypt given base64 encode string content by using private key and return plain message.
       - decryptContent(byte[]): Decrypt given encrypt content by using private key and return plain message.