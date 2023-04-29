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
 * RSA decrypt class.
 * Use for decrypt the RSA encrypt content.
 *
 * @author li1345825138
 * @date 2023/4/24
 */
public class RSADecrypter {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private Cipher cipher;

    private KeyType keyType;

    /**
     * Con-structor for RSA Decrypter
     *
     * @param decryptKeyFilePath where is the key file use for decrypt RSA encrypt message.
     * @param keyType Identify which type of key is pass in.
     * @throws NoSuchAlgorithmException if no Provider supports a KeyFactorySpi implementation
     * for the specified algorithm
     * @throws IOException if an I/O error occurs reading from the file or a malformed or
     * unmappable byte sequence is read
     * @throws InvalidKeySpecException if the given key specification is inappropriate for this
     * key factory to produce a public key.
     * @throws NoSuchPaddingException if transformation contains a padding scheme that is not
     * available.
     */
    public RSADecrypter(String decryptKeyFilePath, KeyType keyType) throws NoSuchAlgorithmException,
            IOException, InvalidKeySpecException, NoSuchPaddingException {
        this.keyType = keyType;
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        String encodedKeyContent = Files.readString(Paths.get(decryptKeyFilePath));
        byte[] keyContentBytes = Base64.getDecoder().decode(encodedKeyContent);
        switch (keyType) {
            case PRIVATE_KEY -> {
                PKCS8EncodedKeySpec encryptKeySpec = new PKCS8EncodedKeySpec(keyContentBytes);
                this.privateKey = keyFactory.generatePrivate(encryptKeySpec);
                this.publicKey = null;
            }
            case PUBLIC_KEY -> {
                X509EncodedKeySpec encryptKeySpec = new X509EncodedKeySpec(keyContentBytes);
                this.publicKey = keyFactory.generatePublic(encryptKeySpec);
                this.privateKey = null;
            }
        }
        this.cipher = Cipher.getInstance("RSA");
    }

    /**
     * Decrypt given base64 encode string content by using private key and return plain message.
     *
     * @param b64EncryptContent base64 encode string content from encrypt plain message
     * @return the plain message after decrypt
     * @throws InvalidKeyException if the given key is inappropriate for initializing this
     * cipher, or its keysize exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files).
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been
     * requested (only in encryption mode), and the total input length of the data processed by
     * this cipher is not a multiple of block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding
     * has been requested, but the decrypted data is not bounded by the appropriate padding bytes
     */
    public String decryptContent(String b64EncryptContent) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        byte[] b64DecodeContent = Base64.getDecoder().decode(b64EncryptContent);
        switch (this.keyType) {
            case PRIVATE_KEY -> this.cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            case PUBLIC_KEY -> this.cipher.init(Cipher.DECRYPT_MODE, this.publicKey);
        }
        byte[] decryptMsg = this.cipher.doFinal(b64DecodeContent);
        return new String(decryptMsg);
    }

    /**
     * Decrypt given encrypt content by using private key and return plain message.
     *
     * @param encryptContent encrypt content from encrypt plain message
     * @return the plain message after decrypt
     * @throws InvalidKeyException if the given key is inappropriate for initializing this
     * cipher, or its keysize exceeds the maximum allowable keysize (as determined from the
     * configured jurisdiction policy files).
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no padding has been
     * requested (only in encryption mode), and the total input length of the data processed by
     * this cipher is not a multiple of block size; or if this encryption algorithm is unable to
     * process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and (un)padding has been
     * requested, but the decrypted data is not bounded by the appropriate padding bytes
     */
    public byte[] decryptContent(byte[] encryptContent) throws InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        switch (this.keyType) {
            case PRIVATE_KEY -> this.cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
            case PUBLIC_KEY -> this.cipher.init(Cipher.DECRYPT_MODE, this.publicKey);
        }
        return this.cipher.doFinal(encryptContent);
    }
}
