import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class App {
    static byte[] buf = new byte[1024];
    static Base64.Encoder enc = Base64.getEncoder();

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
    }
}
