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
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class App {
    static byte[] buf = new byte[1024];
    static Base64.Encoder enc = Base64.getEncoder();
    static Cipher ecipher;
    static Cipher dcipher;

    public static void main(String[] args) throws Exception {

        // Create RSA cipher
        Cipher cipher = Cipher.getInstance("RSA");

        // Create SecureRandom
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");

        // Keys.txt file create and open for write
        String filePath = "keys.txt";
        FileWriter fileWriter = new FileWriter(filePath, false);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        /******Q1************/
        printWriter.println("// Question 1");
        
        // Create key pair generator with RSA
        KeyPairGenerator kpgRSA = KeyPairGenerator.getInstance("RSA");
        // The length of the keys should be at least 1024 bits
        kpgRSA.initialize(1024);

        // Generation an RSA public-private key pairs. Ka(+) and Ka(-)
        KeyPair keyPairRSA = kpgRSA.generateKeyPair();
        PublicKey publicKa = keyPairRSA.getPublic();
        PrivateKey privateKa = keyPairRSA.getPrivate();

        // Create key pair generator with Elliptic-Curve Diffie Helman
        KeyPairGenerator kpgEC = KeyPairGenerator.getInstance("EC");
        // The length of the keys 256 bits
        kpgEC.initialize(256);

        // Generation an Elliptic-Curve Diffie Helman public-private key pairs. Kb(+) and Kb(-)
        KeyPair kpEC = kpgEC.generateKeyPair();
        PublicKey publicKb = kpEC.getPublic();
        PrivateKey privateKb = kpEC.getPrivate();

        // Generation an Elliptic-Curve Diffie Helman public-private key pairs. Kc(+) and Kc(-)
        KeyPair kpEC2 = kpgEC.generateKeyPair();
        PublicKey publicKc = kpEC2.getPublic();
        PrivateKey privateKc = kpEC2.getPrivate();

        // Print file Public-Private key pairs.
        printWriter.println("Public Key Ka(+)\n" + enc.encodeToString(publicKa.getEncoded()));
        printWriter.println("Private Key Ka(-)\n" + enc.encodeToString(privateKa.getEncoded()));
        printWriter.println("Public Key Kb(+)\n" + enc.encodeToString(publicKb.getEncoded()));
        printWriter.println("Private Key Kb(-)\n" + enc.encodeToString(privateKb.getEncoded()));
        printWriter.println("Public Key Kc(+)\n" + enc.encodeToString(publicKc.getEncoded()));
        printWriter.println("Private Key Kc(-)\n" + enc.encodeToString(privateKc.getEncoded()));

        /******Q2************/
        printWriter.println("// Question 2");

        // Generation Symetric keys
        keygenerator.init(128, securerandom);
        SecretKey K1 = keygenerator.generateKey();
        printWriter.println("K1: " + new String(enc.encodeToString(K1.getEncoded())));
        
        keygenerator.init(256, securerandom);
        SecretKey K2 = keygenerator.generateKey();
        printWriter.println("K2: " + new String(enc.encodeToString(K2.getEncoded())));

        // K1 encryption and decryption
        printWriter.println("\nEncryption K1 with Ka(+):");
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encrypted128 = cipher.doFinal((enc.encodeToString(K1.getEncoded())).getBytes());
        printWriter.println(new String(enc.encodeToString(encrypted128)));
        printWriter.println("\nDecryption K1 with with Ka(-):");
        cipher.init(Cipher.DECRYPT_MODE, privateKa);
        byte[] decrypted128 = cipher.doFinal(encrypted128);
        printWriter.println(new String(decrypted128)); // This is a secret message

        // K2 encryption and decryption
        printWriter.println("\n\nEncryption K2 with public key:\n");
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encrypted256 = cipher.doFinal((enc.encodeToString(K2.getEncoded())).getBytes());
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



        /******Q5************/
        printWriter.println("// Question 5");

        // Generate a message authentication code (HMAC-SHA256) using K1 the symmetric keys.
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
  	    sha256_HMAC.init(K1);

        printWriter.close();

    }
}