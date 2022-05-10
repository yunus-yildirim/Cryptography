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

        // Create RSA cipher
        Cipher cipher = Cipher.getInstance("RSA");

        // Create SecureRandom
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance(AES);

        String filePath = "keys.txt";
        FileWriter fileWriter = new FileWriter(filePath, false);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        /******Q1************/
        printWriter.println("// Question 1");

        KeyPairGenerator kpgRSAGenerator = KeyPairGenerator.getInstance("RSA");
        kpgRSAGenerator.initialize(1024);

        KeyPair kpRSA = kpgRSAGenerator.generateKeyPair();
        PrivateKey privateKa = kpRSA.getPrivate();
        PublicKey publicKa = kpRSA.getPublic();

        printWriter.println("Public Key Ka(+): \n" + enc.encodeToString(publicKa.getEncoded()) + "\n");
        printWriter.println("Private Key Ka(-): \n" + enc.encodeToString(privateKa.getEncoded()) + "\n\n");

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

        /******Q2************/
        printWriter.println("// Question 2");

        // Generation Symetric keys
        keygenerator.init(128, securerandom);
        SecretKey symKey128 = keygenerator.generateKey();
        printWriter.println("K1: " + new String(enc.encodeToString(symKey128.getEncoded())));
        
        keygenerator.init(256, securerandom);
        SecretKey symKey256 = keygenerator.generateKey();
        printWriter.println("K2: " + new String(enc.encodeToString(symKey256.getEncoded())));

        // K1 encryption and decryption
        printWriter.println("\nEncryption K1 with Ka(+):");
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encrypted128 = cipher.doFinal((enc.encodeToString(symKey128.getEncoded())).getBytes());
        printWriter.println(new String(enc.encodeToString(encrypted128)));
        printWriter.println("\nDecryption K1 with with Ka(-):");
        cipher.init(Cipher.DECRYPT_MODE, privateKa);
        byte[] decrypted128 = cipher.doFinal(encrypted128);
        printWriter.println(new String(decrypted128)); // This is a secret message

        // K2 encryption and decryption
        printWriter.println("\n\nEncryption K2 with public key:\n");
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encrypted256 = cipher.doFinal((enc.encodeToString(symKey256.getEncoded())).getBytes());
        printWriter.println(new String(enc.encodeToString(encrypted256)));
        printWriter.println("\nDecryption K2 with private key:\n");
        cipher.init(Cipher.DECRYPT_MODE, privateKa);
        byte[] decrypted256 = cipher.doFinal(encrypted256);
        printWriter.println(new String(decrypted256));

        /******Q3************/
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
        printWriter.println("H(m): " + sb.toString());

        // Encryption with Ka(-)
        cipher.init(Cipher.ENCRYPT_MODE, privateKa);
        byte[] encrypt_Hm = cipher.doFinal(message.getBytes());
        printWriter.println("Ka(-)(H(m)): " + new String(enc.encodeToString(encrypt_Hm)));

        // Decryption with Ka(+)
        cipher.init(Cipher.DECRYPT_MODE, publicKa);
        byte[] decHm = cipher.doFinal(encrypt_Hm);
        printWriter.println("Message: " + new String(decHm));

        printWriter.close();

    }
}