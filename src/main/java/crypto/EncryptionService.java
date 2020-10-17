package crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class EncryptionService {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;

    /**
     * AES-GCM inputs - 12 bytes IV, need the same IV and secret keys for encryption and decryption.
     * <p>
     * The output consist of iv, password's salt, encrypted content and auth tag in the following format:
     * output = byte[] {i i i s s s c c c c c c ...}
     * <p>
     * i = IV bytes
     * s = Salt bytes
     * c = content bytes (encrypted content)
    */
    public static byte[] encrypt(byte[] pText, String password) throws Exception {

        // 16 bytes salt
        byte[] salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // GCM recommended 12 bytes iv?
        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // ASE-GCM needs GCMParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(pText);
  
        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();
  
        // it works, even if we save the based64 encoded string into a file.
        // return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
  
        // we save the byte[] into a file.
        return cipherTextWithIvSalt;
    }

    // we need the same password, salt and iv to decrypt it
    private static byte[] decrypt(byte[] cText, String password) throws Exception {

        // get back the iv and salt that was prefixed in the cipher text
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[12];
        bb.get(iv);

        byte[] salt = new byte[16];
        bb.get(salt);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText);

        return plainText;
    }

    // read plain text file and write encrypted bytes to the file
    public static void encryptFile(String fromFile, String toFile, String password) throws Exception {

        // read a normal txt file
        byte[] fileContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(fromFile).toURI()));
    
        // encrypt with a password
        byte[] encryptedText = encrypt(fileContent, password);
    
        // save a file
        Path path = Paths.get(toFile);
    
        Files.write(path, encryptedText);
    }

    // read encrypted file and return byte[]
    public static byte[] decryptFile(String fromEncryptedFile, String password) throws Exception {

        // read a file
        byte[] fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile));
    
        return decrypt(fileContent, password);  
    }
}