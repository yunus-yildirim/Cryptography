import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class App {
    static byte[] buf = new byte[1024];
    static Base64.Encoder enc = Base64.getEncoder();
    static Cipher ecipher;
    static Cipher dcipher;

    public static void main(String[] args) throws Exception {

        // Keys.txt file create and open for write
        String filePath = "keys.txt";
        FileWriter fileWriter = new FileWriter(filePath, false);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        /****** Q1 ************/
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

        // Generation an Elliptic-Curve Diffie Helman public-private key pairs. Kb(+)
        // and Kb(-)
        KeyPair kpEC = kpgEC.generateKeyPair();
        PublicKey publicKb = kpEC.getPublic();
        PrivateKey privateKb = kpEC.getPrivate();

        // Generation an Elliptic-Curve Diffie Helman public-private key pairs. Kc(+)
        // and Kc(-)
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

        /****** Q2 ************/
        printWriter.println("\n// Question 2");

        // Create SecureRandom
        SecureRandom securerandom = new SecureRandom();
        KeyGenerator keygenerator = KeyGenerator.getInstance("AES");

        // Generation Symetric keys
        keygenerator.init(128, securerandom);
        SecretKey K1 = keygenerator.generateKey();
        printWriter.println("K1: " + new String(enc.encodeToString(K1.getEncoded())));

        keygenerator.init(256, securerandom);
        SecretKey K2 = keygenerator.generateKey();
        printWriter.println("K2: " + new String(enc.encodeToString(K2.getEncoded())));

        // Create RSA cipher
        Cipher cipher = Cipher.getInstance("RSA");

        // K1 encryption and decryption
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encryptedK1 = cipher.doFinal((enc.encodeToString(K1.getEncoded())).getBytes());
        printWriter.println("Encryption K1 with Ka(+):" + new String(enc.encodeToString(encryptedK1)));
        cipher.init(Cipher.DECRYPT_MODE, privateKa);
        byte[] decryptedK1 = cipher.doFinal(encryptedK1);
        printWriter.println("Decryption K1 with Ka(-):" + new String(decryptedK1));

        // K2 encryption and decryption
        cipher.init(Cipher.ENCRYPT_MODE, publicKa);
        byte[] encryptedK2 = cipher.doFinal((enc.encodeToString(K2.getEncoded())).getBytes());
        printWriter.println("Encryption K2 with Ka(+):" + new String(enc.encodeToString(encryptedK2)));
        cipher.init(Cipher.DECRYPT_MODE, privateKa);
        byte[] decryptedK2 = cipher.doFinal(encryptedK2);
        printWriter.println("Decryption K2 with Ka(-):" + new String(decryptedK2));

        /****** Q3 ************/
        printWriter.println("\n// Question 3");

        // Get message from file
        byte[] messageBytes = Files.readAllBytes(Paths.get("message.txt"));
        printWriter.println("Message:\n"+new String(messageBytes, StandardCharsets.UTF_8)+"\n");

        // Apply SHA256 Hash algorithm
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageHash = md.digest(messageBytes);
        printWriter.println("H(m): " + new String(messageHash));

        // Encryption H(m) with Private KA
        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKa);
        byte[] digitalSignature = cipher.doFinal(messageHash);
        Files.write(Paths.get("digital_signature"), digitalSignature);
        printWriter.println("Encrypted Message: " + new String(digitalSignature));

        // Decryption Digital signature with public KA
        byte[] encryptedMessageHash = Files.readAllBytes(Paths.get("digital_signature"));
        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.DECRYPT_MODE, publicKa);
        byte[] decryptedMessageHash = cipher2.doFinal(encryptedMessageHash);
        printWriter.println("Decrypted Message: " + new String(decryptedMessageHash));
 
      
        /****** Q4 ************/
        printWriter.println("\n// Question 4");

        byte[] iv = new byte[16];
        AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);

        try {
            ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Encryption AES (K1) in CBC mode
            long startTime = System.nanoTime();
            ecipher.init(Cipher.ENCRYPT_MODE, K1, paramSpec);
            long endTime = System.nanoTime();
            encryptAES(new FileInputStream("image.jpg"), new FileOutputStream("cbc(128)Enc.jpg"));
            long time = endTime - startTime;
            printWriter.println("AES128 in CBC mode encryption: " + time + " nanosecond");

            dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Decryption AES (K1) in CBC mode
            startTime = System.nanoTime();
            dcipher.init(Cipher.DECRYPT_MODE, K1, paramSpec);
            endTime = System.nanoTime();
            decryptAES(new FileInputStream("cbc(128)Enc.jpg"), new FileOutputStream("cbc(128)Dec.jpg"));
            time = endTime - startTime;
            printWriter.println("AES128 in CBC mode decryption: " + time + " nanosecond");

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {

            ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Encryption AES (K2) in CBC mode
            long startTime = System.nanoTime();
            ecipher.init(Cipher.ENCRYPT_MODE, K2, paramSpec);
            long endTime = System.nanoTime();
            encryptAES(new FileInputStream("image.jpg"), new FileOutputStream("cbc(256)Enc.jpg"));
            long time = endTime - startTime;
            printWriter.println("AES256 in CBC mode encryption: " + time + " nanosecond");

            ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            // Decryption AES (K2) in CBC mode
            startTime = System.nanoTime();
            dcipher.init(Cipher.DECRYPT_MODE, K2, paramSpec);
            endTime = System.nanoTime();
            decryptAES(new FileInputStream("cbc(256)Enc.jpg"), new FileOutputStream("cbc(256)Dec.jpg"));
            time = endTime - startTime;
            printWriter.println("AES256 in CBC mode decryption: " + time + " nanosecond");
        } catch (Exception e) {
            e.printStackTrace();
        }

        SecureRandom secureRandom = new SecureRandom();
        // Then generate the key. Can be 128, 192 or 256 bit
        byte[] keyByte = new byte[256 / 8];
        secureRandom.nextBytes(keyByte);
        // Now generate a nonce. You can also use an ever-increasing counter, which is
        // even more secure. NEVER REUSE A NONCE!
        byte[] nonce = new byte[96 / 8];
        secureRandom.nextBytes(nonce);
        iv = new byte[128 / 8];
        System.arraycopy(nonce, 0, iv, 0, nonce.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        ecipher = Cipher.getInstance("AES/CTR/NoPadding");
        // Encryption AES (K3) in CTR mode
        long startTime = System.nanoTime();
        ecipher.init(Cipher.ENCRYPT_MODE, K2, ivSpec);
        long endTime = System.nanoTime();
        encryptAES(new FileInputStream("image.jpg"), new FileOutputStream("ctr(256)Enc.jpg"));
        long time = endTime - startTime;
        printWriter.println("AES256 in CTR mode encryption: " + time + " nanosecond");

        dcipher = Cipher.getInstance("AES/CTR/NoPadding");
        // Encryption AES (K3) in CTR mode
        startTime = System.nanoTime();
        dcipher.init(Cipher.DECRYPT_MODE, K2, ivSpec);
        endTime = System.nanoTime();
        encryptAES(new FileInputStream("ctr(256)Enc.jpg"), new FileOutputStream("ctr(256)Dec.jpg"));
        time = endTime - startTime;
        printWriter.println("AES256 in CTR mode decryption: " + time + " nanosecond");

        /****** Q5 ************/
        printWriter.println("\n// Question 5");

        // Get message from message.txt file
        messageBytes = Files.readAllBytes(Paths.get("message.txt"));

        // Generate a message authentication code (HMAC-SHA256) using K2 the symmetric
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        sha256_HMAC.init(K2);

        printWriter.println("HMAC\n" +enc.encodeToString(sha256_HMAC.doFinal(messageBytes)));

        printWriter.close();

    }

    public static void encryptAES(InputStream in, OutputStream out) {
        try {
            out = new CipherOutputStream(out, ecipher);
            int numRead = 0;
            while ((numRead = in.read(buf)) >= 0) {
                out.write(buf, 0, numRead);
            }
            out.close();
        } catch (java.io.IOException e) {
        }
    }

    public static void decryptAES(InputStream in, OutputStream out) {
        try {
            in = new CipherInputStream(in, dcipher);
            int numRead = 0;
            while ((numRead = in.read(buf)) >= 0) {
                out.write(buf, 0, numRead);
            }
            out.close();
        } catch (java.io.IOException e) {
        }
    }

    public static byte[] signDecrypt(PublicKey publicKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encrypted);
    }

    public static byte[] signEncrypt(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(message.getBytes());
    }
}