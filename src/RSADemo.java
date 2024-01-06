import security.rsa.KeyType;
import security.rsa.RSADecrypter;
import security.rsa.RSAEncrypter;
import security.rsa.RSAKeyGenerator;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class RSADemo {
    public static void main(String[] args) throws Exception {
        // generateKeyPair(2048);
//         textEncrypt();
//         textDecrypt();
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
            StringBuilder sb = new StringBuilder();
            RSADecrypter decrypter = new RSADecrypter("private_key.key", KeyType.PRIVATE_KEY);
            while (bInput.read(content, 0, 344) != -1) {
                byte[] dec_data = decrypter.decryptContent(content);
                sb.append(new String(dec_data));
            }
            System.out.printf(sb.toString());
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
            StringBuilder sb = new StringBuilder();
            RSAEncrypter cipher = new RSAEncrypter("public_key.key", KeyType.PUBLIC_KEY);
            while (bInput.read(content, 0, 10) != -1) {
                byte[] encrypt_data = cipher.encryptContent(content);
                sb.append(new String(encrypt_data));
            }
            bOutput.write(sb.toString().getBytes(StandardCharsets.UTF_8));
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
