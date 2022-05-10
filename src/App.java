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
        PrintWriter writer = new PrintWriter(filePath);
        writer.print("");
        writer.close();

        /// Question 1 - a
        KeyPairGenerator kpgRSAGenerator = KeyPairGenerator.getInstance("RSA");
        kpgRSAGenerator.initialize(1024);

        KeyPair kpRSA = kpgRSAGenerator.generateKeyPair();
        PrivateKey prkRSA = kpRSA.getPrivate();
        PublicKey pukRSA = kpRSA.getPublic();

        try (FileWriter fileWriter = new FileWriter(filePath, true);
                PrintWriter printWriter = new PrintWriter(fileWriter);) {

            printWriter.println("Public Key KA(+): \n" + enc.encodeToString(pukRSA.getEncoded()) + "\n");
            printWriter.println("Private Key KA(-): \n" + enc.encodeToString(prkRSA.getEncoded()) + "\n");
        }

        // Question 1 - b

        KeyPairGenerator kpgECGenerator = KeyPairGenerator.getInstance("EC");
        kpgECGenerator.initialize(256);

        KeyPair kpEC = kpgECGenerator.generateKeyPair();
        PrivateKey prkEC = kpEC.getPrivate();
        PublicKey pukEC = kpEC.getPublic();

        try (FileWriter fileWriter = new FileWriter(filePath, true);
                PrintWriter printWriter = new PrintWriter(fileWriter);) {

            printWriter.println("Public Key KA(+): \n" + enc.encodeToString(pukEC.getEncoded()) + "\n");
            printWriter.println("Private Key KA(-): \n" + enc.encodeToString(prkEC.getEncoded()) + "\n");
        }

    }
}
