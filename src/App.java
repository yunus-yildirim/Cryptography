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

        /// Question 1
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);

        KeyPair kp = kpg.generateKeyPair();
        PrivateKey prk = kp.getPrivate();
        PublicKey puk = kp.getPublic();

        try (FileWriter fileWriter = new FileWriter(filePath, true);
                PrintWriter printWriter = new PrintWriter(fileWriter);) {

            printWriter.println("Public Key KA(+): \n" + enc.encodeToString(puk.getEncoded()) + "\n");
            printWriter.println("Private Key KA(-): \n" + enc.encodeToString(prk.getEncoded()) + "\n");
        }

    }
}
