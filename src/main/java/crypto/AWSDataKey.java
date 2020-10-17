package crypto;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class AWSDataKey {

    public KmsClient kmsInitialization(String keyId) {
        Region region = Region.US_WEST_2;
        KmsClient kmsClient = KmsClient.builder()
                .region(region)
//                .withCredentials(new ProfileCredentialsProvider("security-dev"))
                .build();

        return kmsClient;
    }

    // limitation can only encrypt 4kb of data
     public void encryptData(KmsClient kmsClient, String keyId, String fromFile, String toFile) throws Exception{

         try {
             // read a normal txt file
             byte[] fileContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(fromFile).toURI()));

             SdkBytes myBytes = SdkBytes.fromByteArray(fileContent);

             EncryptRequest encryptRequest = EncryptRequest.builder()
                     .keyId(keyId)
                     .plaintext(myBytes)
                     .build();

             EncryptResponse response = kmsClient.encrypt(encryptRequest);
             String algorithm = response.encryptionAlgorithm().toString();
             System.out.println("The encryption algorithm is " + algorithm);

             // Get the encrypted data
             SdkBytes encryptedData = response.ciphertextBlob();
             // save a file
             Path path = Paths.get(toFile);

             Files.write(path, encryptedData.asByteArray());
         } catch (KmsException e) {
             System.err.println(e.getMessage());
             System.exit(1);
         }
     }
    // snippet-end:[kms.java2_encrypt_data.main]

    // snippet-start:[kms.java2_decrypt_data.main]
    public void decryptData(KmsClient kmsClient, String keyId, String fromEncryptedFile) throws Exception{

    try {
         // read a file
         byte[] fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile));
         SdkBytes encryptedData = SdkBytes.fromByteArray(fileContent);
         DecryptRequest decryptRequest = DecryptRequest.builder()
                 .ciphertextBlob(encryptedData)
                 .keyId(keyId)
                 .build();

         DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);
         SdkBytes plainText = decryptResponse.plaintext();

         System.out.println("After decryption:");
         byte[] pbytes = plainText.asByteArray();
         String pdata = new String(pbytes);
         System.out.println(pdata);

    } catch (KmsException e) {
        System.err.println(e.getMessage());
        System.exit(1);
    }
  }

    public int encryptUsingDataKey(KmsClient kmsClient, String keyId, String fromFile, String toFile)throws Exception {
        try {
            // generateDataKey request to specify the key id and AES spec to be used
            GenerateDataKeyRequest generateDataKeyRequest = GenerateDataKeyRequest
                    .builder().keyId(keyId)
                    .keySpec(DataKeySpec.AES_128).build();

            // Actual data key request
            GenerateDataKeyResponse generateDataKeyResponse = kmsClient.generateDataKey(generateDataKeyRequest);

            // Key is stored as a plaintext in the response
            SecretKeySpec key = new SecretKeySpec(generateDataKeyResponse.plaintext().asByteArray(),"AES");
            Cipher cipher;
            cipher = Cipher.getInstance("AES");
            // Initialing the data key into AES algorithm
            cipher.init(Cipher.ENCRYPT_MODE, key);

            // read a file that needs to be converted
            byte[] fileContent = Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(fromFile).toURI()));

            // actual encryption of the data stored into cipherText
            byte[] cipherText = cipher.doFinal(fileContent);

            // get the encrypted data key that is will stored along with the file for decryption
            SdkBytes encryptedDataKey = generateDataKeyResponse.ciphertextBlob();

            // converting to byte array to be stored to a file
            byte[] encryptedDataKeyByteArray = encryptedDataKey.asByteArray();

            System.out.println("Plaintext Size: "+String.valueOf(fileContent.length) + " bytes");

            System.out.println("Cipher Text Size: "+String.valueOf(cipherText.length) + " bytes");

            System.out.println("Encrypted data key Size: "+String.valueOf(encryptedDataKeyByteArray.length) + " bytes");

            System.out.println("Total encrypted size: "+String.valueOf(cipherText.length + encryptedDataKeyByteArray.length) + " bytes");

            byte[] fileByteArray = new byte[cipherText.length + encryptedDataKeyByteArray.length];

            ByteBuffer buff = ByteBuffer.wrap(fileByteArray);
            buff.put(encryptedDataKeyByteArray);
//            buff.put();
            buff.put(cipherText);

            byte[] combined = buff.array();

            // save a file
            Path path = Paths.get(toFile);

            Files.write(path, combined);

            // returning the key length to identify key vs the cipher text
            return encryptedDataKeyByteArray.length;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return 0;
    }

    public void decryptUsingDataKey(KmsClient kmsClient, String keyId, String fromEncryptedFile, int encryptedKeyLength) {
        SdkBytes encryptedKeySdkBytes;
        try {
            // read the encrypted file
            byte[] fileContent = Files.readAllBytes(Paths.get(fromEncryptedFile));
            ByteBuffer bb = ByteBuffer.wrap(fileContent);

            byte[] encryptedKey = new byte[encryptedKeyLength];
            byte[] cipherText = new byte[fileContent.length - encryptedKeyLength];

            // get the key and cipher text byte array
            bb.get(encryptedKey, 0, encryptedKey.length);
            bb.get(cipherText, 0, cipherText.length);

            // get the plain text data key by sending a request to KMS
            encryptedKeySdkBytes = SdkBytes.fromByteArray(encryptedKey);
            DecryptRequest decryptRequest = DecryptRequest.builder().ciphertextBlob(encryptedKeySdkBytes).build();
            DecryptResponse decryptResponse = kmsClient.decrypt(decryptRequest);

            // initialize AES with the data key
            SecretKeySpec secretKeySpec = new SecretKeySpec(decryptResponse.plaintext().asByteArray(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            System.out.println("After decryption:");
            String plainTextData = new String(cipher.doFinal(cipherText));
            System.out.println(plainTextData);
        } catch(Exception ex) {
            ex.printStackTrace();
        } finally {
            // make sure clear the data key of the memory every time
            encryptedKeySdkBytes = null;
        }
    }

    public static void listAllKeys(KmsClient kmsClient) {

        try {
            ListKeysRequest listKeysRequest = ListKeysRequest.builder()
                    .limit(15)
                    .build();

            ListKeysResponse keysResponse = kmsClient.listKeys(listKeysRequest);
            List<KeyListEntry> keyListEntries = keysResponse.keys();
            for (KeyListEntry key : keyListEntries) {
                System.out.println("The key ARN is: " + key.keyArn());
                System.out.println("The key ID is: " + key.keyId());
            }
        } catch (KmsException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

    }
}