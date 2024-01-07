import security.rsa.KeyType;
import security.rsa.RSADecrypter;
import security.rsa.RSAEncrypter;
import security.rsa.RSAKeyGenerator;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;

public class RSADemo {
    public static void main(String[] args) throws Exception {
//         generateKeyPair(2048);
//         textEncrypt();
         textDecrypt();
        // testRSA1();
        // testRSA2();
    }

    static void textDecrypt() throws Exception {
        try(
                FileInputStream fInput = new FileInputStream("demo_e.txt");
                BufferedInputStream bInput = new BufferedInputStream(fInput)
                ) {
            byte[] content = new byte[344];
            Arrays.fill(content, (byte) 0);
            RSADecrypter decrypter = new RSADecrypter("private_key.key", KeyType.PRIVATE_KEY);
            StringBuilder sb = new StringBuilder();
            while (bInput.read(content, 0, 344) != -1) {
                byte[] dec_data = decrypter.decryptContent(content);
                sb.append(new String(dec_data));
                Arrays.fill(content, (byte) 0);
            }
            System.out.println(sb);
        }
    }

    static void textEncrypt() throws Exception {
        try(
                FileInputStream fInput = new FileInputStream("demo.txt");
                BufferedInputStream bInput = new BufferedInputStream(fInput);
                FileOutputStream fOutput = new FileOutputStream("demo_e.txt");
                BufferedOutputStream bOutput = new BufferedOutputStream(fOutput)
                ) {
            byte[] content = new byte[10];
            Arrays.fill(content, (byte) 0);
            RSAEncrypter cipher = new RSAEncrypter("public_key.key", KeyType.PUBLIC_KEY);
            while (bInput.read(content) != -1) {
                byte[] encrypt_data = cipher.encryptContent(content);
                bOutput.write((new String(encrypt_data)).getBytes());
                Arrays.fill(content, (byte) 0);
            }
        }
    }

    static void generateKeyPair(final int length) throws Exception {
        RSAKeyGenerator keyGenerator = new RSAKeyGenerator(length);
        keyGenerator.generateKeyPair("private_key.key", "public_key.key");
    }

    static void testRSA1() throws Exception {
        // use private key to encrypt message
        RSAEncrypter rsaEncrypter = new RSAEncrypter("private_key.key", KeyType.PRIVATE_KEY);
        String oriMsg = "Hello world";
        String encryptedMsg = rsaEncrypter.encryptContent(oriMsg);
        System.out.println("Encrypt: " + encryptedMsg);

        // use public key to decrypt message
        RSADecrypter rsaDecrypter = new RSADecrypter("public_key.key", KeyType.PUBLIC_KEY);
        System.out.println("Decrypt: " + rsaDecrypter.decryptContent(encryptedMsg));
    }

    static void testRSA2() throws Exception {
        // use public key to encrypt message
        RSAEncrypter rsaEncrypter = new RSAEncrypter("public_key.key", KeyType.PUBLIC_KEY);
        String oriMsg = "Hello world";
        String encryptedMsg = rsaEncrypter.encryptContent(oriMsg);
        System.out.println("Encrypt: " + encryptedMsg);

        // use private key to decrypt message
        RSADecrypter rsaDecrypter = new RSADecrypter("private_key.key", KeyType.PRIVATE_KEY);
        System.out.println("Decrypt: " + rsaDecrypter.decryptContent(encryptedMsg));
    }
}
