package crypto;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class EncryptionViewer {
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static void main(String[] args) throws Exception{
//        String password = "password123";
        String encryptedFileName = "encr.txt";
        String pTextFileName = "file.txt";
//        Normal encryption
//        EncryptionService encrSrv = new EncryptionService();
//        encrSrv.encryptFile(pTextFileName, encryptedFileName, password);
//        System.out.println("Encrypted file stored: "+encryptedFileName);
//
//        byte[] decryptedText = encrSrv.decryptFile(encryptedFileName, password);
//        String pText = new String(decryptedText, UTF_8);
//        System.out.println("Decrypted Data: "+pText);

        // AWS KMS Encryption
        String keyId = "e4d63022-8ea2-4289-bc79-575c9eef895c";
        AWSDataKey kms = new AWSDataKey();
        KmsClient kmsClient = kms.kmsInitialization(keyId);

        // can be utilized for files less than 4KB
        kms.encryptData(kmsClient, keyId, pTextFileName, encryptedFileName);
        kms.decryptData(kmsClient, keyId, encryptedFileName);

        // for files more than for 4KB need to utilize data keys
        int keyLength = kms.encryptUsingDataKey(kmsClient, keyId, pTextFileName, encryptedFileName);
        kms.decryptUsingDataKey(kmsClient, keyId, encryptedFileName, keyLength);
    }
  }