//Ohta Kamiya and Casey Malcolm
import java.io.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PasswordManager {
    private static SecretKeySpec key;
    private static byte[] salt;
    private static final String saltString = "uTsVP9BNAzz6xH2caZEUdw==";

    public static void main(String[] args) throws Exception {

        boolean running = true;
        File file = new File("src/password_manager_file.txt");

        while (running) {
            // Check if password file exists
            if (file.exists()) {
                System.out.println("Password file exists.");
                System.out.println("Enter the password to access the master list of passwords: ");
                Scanner scanner = new Scanner(System.in);
                String inputMasterPassword = scanner.nextLine();

                salt = byteSalt(saltString);
                key = createKey(inputMasterPassword, salt);


                BufferedReader reader = new BufferedReader(new FileReader(file));
                String firstLine = reader.readLine();

                String[] firstLineArray = firstLine.split(":");
                String storedSalt = firstLineArray[0];
                String storedMasterPassword = firstLineArray[1];
                String decryptedPassword = decrypt(storedMasterPassword);


                if(!decryptedPassword.equals(inputMasterPassword)){
                    System.out.print("Wrong Password");
                    System.exit(0);
                }

                // Check if inputMasterPassword matches the storedMasterPassword
                // Decrypt storedMasterPassword

                boolean choosing = true;
                while (choosing) {
                    String choice = chooseFunction();

                    if (choice.equals("a")) {
                        addPassword(key);
                    } else if (choice.equals("r")) {
                        readPassword(key, inputMasterPassword);
                    } else if (choice.equals("q")) {
                        System.exit(0);
                    } else {
                        // They entered something other than the three options
                        continue;
                    }
                }

            } else {
                Scanner scanner = new Scanner(System.in);
                System.out.println("Password file does not exist.");
                System.out.println("Enter new password to create a password file: ");
                String inputMasterPassword = scanner.nextLine();

                salt = byteSalt(saltString);
                key = createKey(inputMasterPassword, salt);

                file.createNewFile();
                BufferedWriter writer = new BufferedWriter(new FileWriter("src/password_manager_file.txt"));
                String encryptedMasterPassword = encrypt(inputMasterPassword);
                writer.write(saltString + ":" + encryptedMasterPassword);
                writer.newLine();
                writer.close();
            }
        }
    }

    public static String chooseFunction() {
        System.out.println("What would you like to do? ");
        System.out.println("a : Add Password");
        System.out.println("r : Read Password");
        System.out.println("q : Quit");
        System.out.println("Enter choice: ");
        Scanner scanner = new Scanner(System.in);
        String choice = scanner.nextLine().toLowerCase();
        if (choice.equals("a") | (choice.equals("r")) | (choice.equals("q"))) {
            return choice;
        }
        System.out.println("You must enter a, r, or q");
        return "null";
    }

    public static void addPassword(SecretKeySpec key) throws Exception{
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Label for password: ");
        String label = scanner.nextLine();

        System.out.print("Enter password to store: ");
        String password = scanner.nextLine();
        String encryptedPassword = encrypt(password);

        BufferedWriter writer = new BufferedWriter(new FileWriter("src/password_manager_file.txt", true));
        String addToFile = label + ":" + encryptedPassword;
        writer.write(addToFile);
        writer.newLine();
        writer.close();
    }

    public static void readPassword(SecretKeySpec key, String masterPassword) throws Exception {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Label for password: ");
        String label = scanner.nextLine();

        BufferedReader reader = new BufferedReader(new FileReader("src/password_manager_file.txt"));
        String line;
        String password;
        boolean found = false;

        while((line = reader.readLine()) != null){
            if(line.startsWith(label + ":")){
                found = true;
                String[] parts = line.split(":");
                password = parts[1];
                password = decrypt(password);
                System.out.println("Found: " + password);
            }
        }

        if(!found){
            System.out.println("Password not found");
        }

        reader.close();
    }


    public static String encrypt(String masterPassword) throws Exception {

        Cipher cipher = Cipher.getInstance("AES"); // does the encryption
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal(masterPassword.getBytes());
        return new String(Base64.getEncoder().encode(encryptedPassword));
    }

    public static String decrypt(String encryptedPassword) throws Exception {

        try {
            Cipher cipher = Cipher.getInstance("AES");
            byte[] decoded = Base64.getDecoder().decode(encryptedPassword);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        } catch( Exception e){
            return "Wrong Password";
        }

    }

    public static SecretKeySpec createKey(String password, byte[] salt) throws Exception{
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte[] encoded = sharedKey.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    public static byte[] byteSalt(String saltString){
        byte[] salt = new byte[16];
        return Base64.getDecoder().decode(saltString);
    }
}
