package security.rsa;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * RSA encrypt and decrypt class.
 * This is just wrap around standard encrypt API make easy to use.
 * Before using this encrypts/decrypts class please use RSAKeyGenerator to generate private and
 * public key first, because this class ctor is asking for private and public key file for doing
 * message encrypt and decrypt.
 *
 * @author li1345825138
 * @date 2023/4/24
 */
public class RSAEncrypter {
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private Cipher cipher;

    private KeyType keyType;

    /**
     * Con-structure
     * Initialize both private and public key from given key files
     *
     * @param encryptKeyPath where the key use for encrypt is located at.
     * @param keyType Identify which type of key is pass in.
     * @throws IOException if an I/O error occurs reading from the file or a
     * malformed or unmappable byte sequence is read
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi implementation
     * for the specified algorithm
     * @throws InvalidKeySpecException  if the given key specification is inappropriate for this
     * key factory to produce a public key.
     * @throws NoSuchPaddingException if transformation contains a padding scheme that is not
     * available.
     */
    public RSAEncrypter(String encryptKeyPath, KeyType keyType) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException {
        this.keyType = keyType;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        String encodeContent = Files.readString(Paths.get(encryptKeyPath));
        byte[] keyContentByte = Base64.getDecoder().decode(encodeContent);

        switch (keyType) {
            case PRIVATE_KEY -> {
                PKCS8EncodedKeySpec encryptKeySpec = new PKCS8EncodedKeySpec(keyContentByte);
                this.privateKey = keyFactory.generatePrivate(encryptKeySpec);
                this.publicKey = null;
            }
            case PUBLIC_KEY -> {
                X509EncodedKeySpec encryptKeySpec = new X509EncodedKeySpec(keyContentByte);
                this.publicKey = keyFactory.generatePublic(encryptKeySpec);
                this.privateKey = null;
            }
        }

        this.cipher = Cipher.getInstance("RSA");
    }

    /**
     * Encrypt given string content by using private key
     *
     * @param originalMsg the original plain message ready for encrypt
     * @return base64 encode string content from encrypt plain message
     * @throws InvalidKeyException if the given key is inappropriate for initializing this
     * cipher, or its keysize exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files).
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been
     * requested (only in encryption mode), and the total input length of the data processed by
     * this cipher is not a multiple of block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been
     * requested, but the decrypted data is not bounded by the appropriate padding bytes (only in
     * decryption mode).
     */
    public String encryptContent(String originalMsg) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        switch (this.keyType) {
            case PRIVATE_KEY -> this.cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
            case PUBLIC_KEY -> this.cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        }
        byte[] encryptContent = this.cipher.doFinal(originalMsg.getBytes());
        return Base64.getEncoder().encodeToString(encryptContent);
    }

    /**
     * Encrypt any original byte array content into encrypted byte array by using private key.
     *
     * @param originalMsg original byte array content
     * @return encrypted byte array content with base64 encoded
     * @throws InvalidKeyException if the given key is inappropriate for initializing this
     * cipher, or its keysize exceeds the maximum allowable keysize (as determined from
     * theconfigured jurisdiction policy files).
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been
     * requested (only in encryption mode), and the total input length of the data processed by
     * this cipher is not a multiple of block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been
     * requested, but the decrypted data is not bounded by the appropriate padding bytes (only in
     * decryption mode).
     */
    public byte[] encryptContent(byte[] originalMsg) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        switch (this.keyType) {
            case PRIVATE_KEY -> this.cipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
            case PUBLIC_KEY -> this.cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        }
        byte[] encryptContent = this.cipher.doFinal(originalMsg);
        return Base64.getEncoder().encode(encryptContent);
    }
}
