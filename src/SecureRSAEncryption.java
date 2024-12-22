import java.security.*;
import javax.crypto.Cipher;

public class SecureRSAEncryption {

    // Set a unique identifier for the host machine
    private static final String HOST_IDENTIFIER = "YourHostIdentifier";

    public static void main(String[] args) {
        try {
            // Check if the program is running on the host machine
            if (isHostMachine()) {
                // Generate key pair
                KeyPair keyPair = generateKeyPair();

                // Get public and private keys
                PublicKey publicKey = keyPair.getPublic();
                PrivateKey privateKey = keyPair.getPrivate();

                // Simulate data (customer information)
                String customerData = "Customer123";
                System.out.println("Original data: " + customerData);

                // Encrypt data using the public key
                byte[] encryptedData = encrypt(customerData, publicKey);

                // Decrypt data using the private key
                String decryptedData = decrypt(encryptedData, privateKey);
                System.out.println("Decrypted data: " + decryptedData);
            } else {
                System.out.println("This program can only run on the designated host machine.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Check if the program is running on the host machine
    private static boolean isHostMachine() {
        // Implement logic to identify the host machine (e.g., compare identifiers)
        // Replace the following line with your own logic
        return HOST_IDENTIFIER.equals(System.getenv("HOST_IDENTIFIER"));
    }

    
    // Generate RSA key pair
    private static KeyPair generateKeyPair() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048); // Key size
        return keyPairGenerator.generateKeyPair();
    }

    // Encrypt data using RSA public key
    private static byte[] encrypt(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    // Decrypt data using RSA private key
    private static String decrypt(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
}


