import security.rsa.RSADecrypter;
import security.rsa.RSAEncrypter;
import security.rsa.RSAKeyGenerator;

public class RSADemo {
    public static void main(String[] args) throws Exception {
        // generateKeyPair();
        // testRSA1();
        // testRSA2();
    }

    static void generateKeyPair() throws Exception {
        RSAKeyGenerator keyGenerator = new RSAKeyGenerator(1024);
        keyGenerator.generateKeyPair("private_key.key", "public_key.key");
    }

    static void testRSA1() throws Exception {
        // use private key to encrypt message
        RSAEncrypter rsaEncrypter = new RSAEncrypter("private_key.key", RSAEncrypter.KeyIdentify.PRIVATE_KEY);
        String oriMsg = "Hello world";
        String encryptedMsg = rsaEncrypter.encryptContent(oriMsg);
        System.out.println("Encrypt: " + encryptedMsg);

        // use public key to decrypt message
        RSADecrypter rsaDecrypter = new RSADecrypter("public_key.key", RSADecrypter.KeyIdentify.PUBLIC_KEY);
        System.out.println("Decrypt: " + rsaDecrypter.decryptContent(encryptedMsg));
    }

    static void testRSA2() throws Exception {
        // use public key to encrypt message
        RSAEncrypter rsaEncrypter = new RSAEncrypter("public_key.key", RSAEncrypter.KeyIdentify.PUBLIC_KEY);
        String oriMsg = "Hello world";
        String encryptedMsg = rsaEncrypter.encryptContent(oriMsg);
        System.out.println("Encrypt: " + encryptedMsg);

        // use private key to decrypt message
        RSADecrypter rsaDecrypter = new RSADecrypter("private_key.key", RSADecrypter.KeyIdentify.PRIVATE_KEY);
        System.out.println("Decrypt: " + rsaDecrypter.decryptContent(encryptedMsg));
    }
}
