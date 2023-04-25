package security.rsa;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

/**
 * RSA Key Pair Generator
 * This class is just wrap around standard RSA algorithm from jdk RSA algorithm make easy to use.
 * @author li1345825138
 * @date 2023/4/23
 */
public class RSAKeyGenerator {

    // standard key pair generator
    private final KeyPairGenerator keyPairGenerator;

    // standard key pair to get private and public key content
    private KeyPair keyPair;

    /**
     * ctor to initialize the class
     * @param keyLength how long the key is, the key length range cannot less than 1024.
     * If key length is less than 1024, will automatically set back to 1024.
     * @throws NoSuchAlgorithmException This exception should never be triggered.
     * @throws NullPointerException This exception should never be triggered.
     */
    public RSAKeyGenerator(int keyLength) throws NoSuchAlgorithmException, NullPointerException {
        if (keyLength < 1024) keyLength = 1024;
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        this.keyPairGenerator.initialize(keyLength);
        this.keyPair = this.keyPairGenerator.generateKeyPair();
    }

    /**
     * Output private key file by given path.
     * @param privateKeyPath the location of path where going to output private key file with specific file name
     * @throws IOException if an I/O error occurs writing to or creating the file, or the text cannot be encoded using UTF-8.
     * @throws InvalidPathException if the path string cannot be converted to a Path.
     */
    private void outputPrivateKey(String privateKeyPath) throws IOException, InvalidPathException {
        RSAPrivateKey privateKey = (RSAPrivateKey) this.keyPair.getPrivate();
        byte[] encoded = privateKey.getEncoded();
        Files.writeString(Paths.get(privateKeyPath), Base64.getEncoder().encodeToString(encoded));
    }

    /**
     * Output public key file by given path
     * @param publicKeyPath the location of path where going to output public key file with specific file name
     * @throws IOException if an I/O error occurs writing to or creating the file, or the text cannot be encoded using UTF-8.
     * @throws InvalidPathException if the path string cannot be converted to a Path.
     */
    private void outputPublicKey(String publicKeyPath) throws IOException, InvalidPathException {
        RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
        byte[] encoded = publicKey.getEncoded();
        Files.writeString(Paths.get(publicKeyPath), Base64.getEncoder().encodeToString(encoded));
    }

    /**
     * Output private and public key file by given two key file path.
     * @param privateKeyPath private key file path with specific file name
     * @param publicKeyPath public key file path with specific file name
     * @throws IOException if an I/O error occurs writing to or creating the file, or the text cannot be encoded using UTF-8.
     * @throws InvalidPathException if the path string cannot be converted to a Path.
     */
    public void generateKeyPair(String privateKeyPath, String publicKeyPath) throws IOException, InvalidPathException {
        outputPrivateKey(privateKeyPath);
        outputPublicKey(publicKeyPath);
    }
}
