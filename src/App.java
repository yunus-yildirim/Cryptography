import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class App {
    static byte[] buf = new byte[1024];
    static Base64.Encoder enc = Base64.getEncoder();

    public static void main(String[] args) throws Exception {

        String filePath = "Keys.txt";
        FileWriter fileWriter = new FileWriter(filePath, false);
        PrintWriter printWriter = new PrintWriter(fileWriter);

        /// Question 1 - a
        KeyPairGenerator kpgRSAGenerator = KeyPairGenerator.getInstance("RSA");
        kpgRSAGenerator.initialize(1024);

        KeyPair kpRSA = kpgRSAGenerator.generateKeyPair();
        PrivateKey privateKa = kpRSA.getPrivate();
        PublicKey publicKa = kpRSA.getPublic();

        printWriter.println("Public Key KA(+): \n" + enc.encodeToString(publicKa.getEncoded()) + "\n");
        printWriter.println("Private Key KA(-): \n" + enc.encodeToString(privateKa.getEncoded()) + "\n");

        // Question 1 - b

        KeyPairGenerator kpgECGenerator = KeyPairGenerator.getInstance("EC");
        kpgECGenerator.initialize(256);

        KeyPair kpEC = kpgECGenerator.generateKeyPair();
        PrivateKey privateKb = kpEC.getPrivate();
        PublicKey publicKb = kpEC.getPublic();
        KeyPair kpEC2 = kpgECGenerator.generateKeyPair();
        PrivateKey privateKc = kpEC2.getPrivate();
        PublicKey publicKc = kpEC2.getPublic();

        printWriter.println("Public Key KB(+): \n" + enc.encodeToString(publicKb.getEncoded()) + "\n");
        printWriter.println("Private Key KB(-): \n" + enc.encodeToString(privateKb.getEncoded()) + "\n");
        printWriter.println("Public Key KC(+): \n" + enc.encodeToString(publicKc.getEncoded()) + "\n");
        printWriter.println("Private Key KC(-): \n" + enc.encodeToString(privateKc.getEncoded()) + "\n");

        printWriter.close();
    }
}
