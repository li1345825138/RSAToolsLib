import security.rsa.KeyType;
import security.rsa.RSADecrypter;
import security.rsa.RSAEncrypter;
import security.rsa.RSAKeyGenerator;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.RandomAccessFile;
import java.util.Arrays;

public class RSADemo {
    private static int KEY_LENGTH = 2048;
    public static void main(String[] args) throws Exception {
//         generateKeyPair(KEY_LENGTH);
//         textEncrypt();
//         textDecrypt();
//         testRSA1();
//         testRSA2();
    }

    static void textDecrypt() throws Exception {
        try(
                RandomAccessFile rInput = new RandomAccessFile("demo_e.txt", "r");
                ) {
            int encryptSize = rInput.readInt();
            byte[] content = new byte[encryptSize];
            Arrays.fill(content, (byte) 0);
            RSADecrypter decrypter = new RSADecrypter("private_key.key", KeyType.PRIVATE_KEY);
            StringBuilder sb = new StringBuilder();
            while (rInput.read(content, 0, encryptSize) != -1) {
                byte[] dec_content = decrypter.decryptContent(content);
                sb.append(new String(dec_content));
                Arrays.fill(content, (byte) 0);
            }
            System.out.println(sb);
        }
    }

    static void textEncrypt() throws Exception {
        try(
                FileInputStream fInput = new FileInputStream("demo.txt");
                BufferedInputStream bInput = new BufferedInputStream(fInput);
                RandomAccessFile rOut = new RandomAccessFile("demo_e.txt", "rw");
                ) {
            rOut.setLength(0L);
            byte[] content = new byte[10];
            Arrays.fill(content, (byte) 0);
            if (bInput.read(content) == -1) return;
            RSAEncrypter cipher = new RSAEncrypter("public_key.key", KeyType.PUBLIC_KEY);

            // run this for write out length of base64 encrypt string and first string content
            byte[] encrypt_data = cipher.encryptContent(content);
            rOut.writeInt(encrypt_data.length);
            rOut.write((new String(encrypt_data)).getBytes());
            Arrays.fill(content, (byte) 0);

            // do the rest
            while (bInput.read(content, 0, 10) != -1) {
                encrypt_data = cipher.encryptContent(content);
                rOut.write((new String(encrypt_data)).getBytes());
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
