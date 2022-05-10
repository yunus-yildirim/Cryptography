import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class App {
    static byte[] buf = new byte[1024];
    static Base64.Encoder enc = Base64.getEncoder();
    static Cipher ecipher;
    static Cipher dcipher;
    public static final String AES = "AES";

    public static void main(String[] args) throws Exception {

        String filePath = "keys.txt";
        FileWriter fileWriter = new FileWriter(filePath, false);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        // Question 1 - a
        printWriter.println("// Question 1 - a\n");

        KeyPairGenerator kpgRSAGenerator = KeyPairGenerator.getInstance("RSA");
        kpgRSAGenerator.initialize(1024);

        KeyPair kpRSA = kpgRSAGenerator.generateKeyPair();
        PrivateKey privateKa = kpRSA.getPrivate();
        PublicKey publicKa = kpRSA.getPublic();

        printWriter.println("Public Key Ka(+): \n" + enc.encodeToString(publicKa.getEncoded()) + "\n");
        printWriter.println("Private Key Ka(-): \n" + enc.encodeToString(privateKa.getEncoded()) + "\n\n");

        // Question 1 - b
        printWriter.println("// Question 1 - b\n");

        KeyPairGenerator kpgECGenerator = KeyPairGenerator.getInstance("EC");
        kpgECGenerator.initialize(256);

        KeyPair kpEC = kpgECGenerator.generateKeyPair();
        PrivateKey privateKb = kpEC.getPrivate();
        PublicKey publicKb = kpEC.getPublic();
        KeyPair kpEC2 = kpgECGenerator.generateKeyPair();
        PrivateKey privateKc = kpEC2.getPrivate();
        PublicKey publicKc = kpEC2.getPublic();

        printWriter.println("Public Key Kb(+): \n" + enc.encodeToString(publicKb.getEncoded()) + "\n");
        printWriter.println("Private Key Kb(-): \n" + enc.encodeToString(privateKb.getEncoded()) + "\n");
        printWriter.println("Public Key Kc(+): \n" + enc.encodeToString(publicKc.getEncoded()) + "\n");
        printWriter.println("Private Key Kc(-): \n" + enc.encodeToString(privateKc.getEncoded()) + "\n\n");
        
        // Question 3
        printWriter.println("// Question 3");

        // Get message from file
        String message = "";
        File myObj = new File("message.txt");
        try (Scanner myReader = new Scanner(myObj)) {
            while (myReader.hasNextLine()) {
                message = myReader.nextLine();
            }
        }

        // Apply SHA256 Hash algorithm (Obtain the message digest, H(m))
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashInBytes = md.digest(message.getBytes(StandardCharsets.UTF_8));

        // bytes to hex
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        printWriter.println("\nH(m): " + sb.toString());

        //Create RSA cipher
        Cipher cipher = Cipher.getInstance("RSA");
        // Encryption with Ka(-)
        cipher.init(Cipher.ENCRYPT_MODE, privateKa);
        byte [] encrypt_Hm = cipher.doFinal(message.getBytes());
        printWriter.println("\nKa(-)(H(m)): "+new String(enc.encodeToString(encrypt_Hm)));

        // Decryption with Ka(+)
        cipher.init(Cipher.DECRYPT_MODE, publicKa);
        byte[] decHm = cipher.doFinal(encrypt_Hm);                                 
        printWriter.println("\nMessage: " +new String(decHm));  


        
        printWriter.close();

        // Question 2

        SecretKey symKey128 = generateAESKey(128);
        System.out.println("K1: " + new String(enc.encodeToString(symKey128.getEncoded())) + "\n");
        SecretKey symKey256 = generateAESKey(256);
        System.out.println("K2: " + new String(enc.encodeToString(symKey256.getEncoded())) + "\n");

        System.out.println("Encryption K1 with public key:\n");
        byte[] encrypted128 = encrypt(publicKa, new String(enc.encodeToString(symKey128.getEncoded())));
        System.out.println(new String(enc.encodeToString(encrypted128)));
        System.out.println("\nDecryption K1 with private key:\n");
        byte[] decrypted128 = decrypt(privateKa, encrypted128);
        System.out.println(new String(decrypted128)); // This is a secret message

        System.out.println("\n\nEncryption K2 with public key:\n");
        byte[] encrypted256 = encrypt(publicKa, new String(enc.encodeToString(symKey256.getEncoded())));
        System.out.println(new String(enc.encodeToString(encrypted256)));
        System.out.println("\nDecryption K2 with private key:\n");
        byte[] decrypted256 = decrypt(privateKa, encrypted256);
        System.out.println(new String(decrypted256));

    }

    public static SecretKey generateAESKey(int bit)
            throws Exception {
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        keygenerator.init(bit, securerandom);
        SecretKey key = keygenerator.generateKey();

        return key;
    }

    // Question 2

    public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encrypted);
    }

    public static byte[] encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

}