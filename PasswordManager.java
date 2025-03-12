import java.io.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class PasswordManager {
    private static SecretKeySpec key;
    private static byte[] salt;
    private static final String saltString = "uTsVP9BNAzz6xH2caZEUdw=="; // Predefined salt string

    public static void main(String[] args) throws Exception {

        boolean running = true;
        File file = new File("src/password_manager_file.txt"); // File to store encrypted passwords

        while (running) {
            // Check if password file exists
            if (file.exists()) {
                System.out.println("Password file exists.");
                System.out.println("Enter the password to access the master list of passwords: ");
                Scanner scanner = new Scanner(System.in);
                String inputMasterPassword = scanner.nextLine();

                salt = byteSalt(saltString); // Convert salt string to byte array
                key = createKey(inputMasterPassword, salt); // Generate key using password and salt

                BufferedReader reader = new BufferedReader(new FileReader(file));
                String firstLine = reader.readLine(); // Read the first line containing master password

                String[] firstLineArray = firstLine.split(":");
                String storedSalt = firstLineArray[0];
                String storedMasterPassword = firstLineArray[1];
                String decryptedPassword = decrypt(storedMasterPassword); // Decrypt stored master password

                // Check if entered password matches stored password
                if (!decryptedPassword.equals(inputMasterPassword)) {
                    System.out.print("Wrong Password");
                    System.exit(0);
                }

                boolean choosing = true;
                while (choosing) {
                    String choice = chooseFunction(); // Prompt user for action

                    if (choice.equals("a")) {
                        addPassword(key); // Add a new password
                    } else if (choice.equals("r")) {
                        readPassword(key, inputMasterPassword); // Retrieve a stored password
                    } else if (choice.equals("q")) {
                        System.exit(0); // Quit program
                    } else {
                        continue; // Invalid input, re-prompt user
                    }
                }
            } else {
                // If file does not exist, create a new password file
                Scanner scanner = new Scanner(System.in);
                System.out.println("Password file does not exist.");
                System.out.println("Enter new password to create a password file: ");
                String inputMasterPassword = scanner.nextLine();

                salt = byteSalt(saltString);
                key = createKey(inputMasterPassword, salt);

                file.createNewFile();
                BufferedWriter writer = new BufferedWriter(new FileWriter("src/password_manager_file.txt"));
                String encryptedMasterPassword = encrypt(inputMasterPassword); // Encrypt master password
                writer.write(saltString + ":" + encryptedMasterPassword);
                writer.newLine();
                writer.close();
            }
        }
    }

    public static String chooseFunction() {
        // Prompt user to choose an action
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

    public static void addPassword(SecretKeySpec key) throws Exception {
        // Function to add a new password
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Label for password: ");
        String label = scanner.nextLine();

        System.out.print("Enter password to store: ");
        String password = scanner.nextLine();
        String encryptedPassword = encrypt(password); // Encrypt password

        BufferedWriter writer = new BufferedWriter(new FileWriter("src/password_manager_file.txt", true));
        String addToFile = label + ":" + encryptedPassword;
        writer.write(addToFile);
        writer.newLine();
        writer.close();
    }

    public static void readPassword(SecretKeySpec key, String masterPassword) throws Exception {
        // Function to retrieve a password by label
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Label for password: ");
        String label = scanner.nextLine();

        BufferedReader reader = new BufferedReader(new FileReader("src/password_manager_file.txt"));
        String line;
        String password;
        boolean found = false;

        while ((line = reader.readLine()) != null) {
            if (line.startsWith(label + ":")) {
                found = true;
                String[] parts = line.split(":");
                password = parts[1];
                password = decrypt(password); // Decrypt stored password
                System.out.println("Found: " + password);
            }
        }

        if (!found) {
            System.out.println("Password not found");
        }

        reader.close();
    }

    public static String encrypt(String masterPassword) throws Exception {
        // Encrypts a password using AES
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal(masterPassword.getBytes());
        return new String(Base64.getEncoder().encode(encryptedPassword));
    }

    public static String decrypt(String encryptedPassword) throws Exception {
        // Decrypts a password using AES
        try {
            Cipher cipher = Cipher.getInstance("AES");
            byte[] decoded = Base64.getDecoder().decode(encryptedPassword);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = cipher.doFinal(decoded);
            return new String(decrypted);
        } catch (Exception e) {
            return "Wrong Password";
        }
    }

    public static SecretKeySpec createKey(String password, byte[] salt) throws Exception {
        // Generates a SecretKeySpec using PBKDF2 with SHA-256
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey sharedKey = factory.generateSecret(spec);
        byte[] encoded = sharedKey.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    public static byte[] byteSalt(String saltString) {
        // Converts Base64 encoded salt string to byte array
        return Base64.getDecoder().decode(saltString);
    }
}
