import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class App {
	static byte[] buf = new byte[1024];
	static Base64.Encoder enc = Base64.getEncoder();
    
    public static void main(String[] args) throws Exception {
        
        /// Question 1       	
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");     
        kpg.initialize(1024);   
        
        KeyPair kp = kpg.generateKeyPair();   
        PrivateKey prk = kp.getPrivate();   
        PublicKey puk = kp.getPublic();
        
        try {
            File myObj = new File("Keys.txt");
            if (myObj.createNewFile()) {
              System.out.println("File created: " + myObj.getName());
            } else {
              System.out.println("File already exists.");
            }
          } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }

          try {
            FileWriter myWriter = new FileWriter("Keys.txt");
            myWriter.write("Public Key KA(+): \n" + enc.encodeToString(puk.getEncoded()) + "\n" 
            + "Private Key KA(-): \n" + enc.encodeToString(prk.getEncoded()) + "\n\n");
            myWriter.close();
          } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }
    }
}
