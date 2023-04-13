package me.xe_55;

import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    // encryption and decryption parameters
    private static final int KEY_SIZE = 256; // AES-256 bit key size
    private static final int ITERATIONS = 65536; // PBKDF2 iteration count
    private static final int SALT_SIZE = 16; // salt size for PBKDF2
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SECRET_KEY_SPEC_SCHEME = "PBKDF2WithHmacSHA256";

    // crypto random number generator
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static void main(String[] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        // create socket and connect to server
        Socket socket = new Socket("localhost", 8888);

        // create input and output streams for client socket
        SecretKey sessionKey = initSession(socket);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(getCipherInputStream(socket.getInputStream(), sessionKey)));
        PrintWriter out = new PrintWriter(getCipherOutputStream(socket.getOutputStream(), sessionKey), true);

        // start new thread to read messages from server
        new Thread(() -> {
            try {
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    System.out.println("SERVER: "+ decryptMessage(inputLine, sessionKey));
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();

        // start new thread to read console input and send to server
        new Thread(() -> {
            try {
                BufferedReader consoleIn = new BufferedReader(new InputStreamReader(System.in));
                String inputLine;
                while ((inputLine = consoleIn.readLine()) != null) {
                    String encryptedMessage = encryptMessage(inputLine, sessionKey);
                    out.println(encryptedMessage);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }).start();
    }
    
    /*
     * Initializes a session with the server and returns the session key.
     */
    private static SecretKey initSession(Socket socket) throws IOException {
        System.out.println("Connected to server: " + socket.getInetAddress().getHostAddress());
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        try {
            // read salt and initialization vector from server
            System.out.println("Waiting for salt and IV from server...");
            String saltLine = in.readLine();
            byte[] salt = Base64.getDecoder().decode(saltLine.split(": ")[1]);
            System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
            String ivLine = in.readLine();
            byte[] iv = Base64.getDecoder().decode(ivLine.split(": ")[1]);
            System.out.println("IV: " + Base64.getEncoder().encodeToString(iv));

            // create and send key encrypted with server public key
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            byte[] encryptedKey = encryptWithServerPublicKey(privateKey, salt, iv);
            out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            out.println(Base64.getEncoder().encodeToString(encryptedKey));
            System.out.println("Session key sent to server.");
            return deriveKeyFromPassword(System.console().readPassword("Enter password: "), salt);
        } catch (NoSuchAlgorithmException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
            throw new RuntimeException("Error initializing session with server", e);
        }
    }
    
    /*
     * Encrypts a secret key using the server's public key, salt, and initialization vector.
     */
    private static byte[] encryptWithServerPublicKey(PrivateKey privateKey, byte[] salt, byte[] iv)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(baos);
        out.writeInt(salt.length);
        out.write(salt);
        out.writeInt(iv.length);
        out.write(iv);
        byte[] encryptedKey = cipher.doFinal(baos.toByteArray());
        return encryptedKey;
    }

    /*
     * Derives a secret key from a password and salt using PBKDF2.
     */
    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) {
        try {
            KeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_SPEC_SCHEME);
            byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
            return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to generate secret key from password and salt", e);
        }
    }

    /*
     * Encrypts a message using AES/CBC/PKCS5Padding encryption.
     */
    private static String encryptMessage(String message, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            IvParameterSpec iv = generateIV();
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] ciphertextBytes = cipher.doFinal(message.getBytes());
            byte[] messageBytes = new byte[ciphertextBytes.length + iv.getIV().length];
            System.arraycopy(iv.getIV(), 0, messageBytes, 0, iv.getIV().length);
            System.arraycopy(ciphertextBytes, 0, messageBytes, iv.getIV().length, ciphertextBytes.length);
            return Base64.getEncoder().encodeToString(messageBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed to encrypt message", e);
        }
    }

    /*
     * Decrypts a message using AES/CBC/PKCS5Padding encryption.
     */
    private static String decryptMessage(String ciphertext, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            byte[] messageBytes = Base64.getDecoder().decode(ciphertext);
            IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(messageBytes, 0, SALT_SIZE));
            byte[] ciphertextBytes = Arrays.copyOfRange(messageBytes, SALT_SIZE, messageBytes.length);
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] plaintextBytes = cipher.doFinal(ciphertextBytes);
            return new String(plaintextBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException("Failed to decrypt message", e);
        }
    }

    /*
     * Generates a new initialization vector using a crypto random number generator.
     */
    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[KEY_SIZE/8];
        SECURE_RANDOM.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /*
     * Returns an input stream that decrypts data using a specified secret key and initialization vector.
     */
    private static InputStream getCipherInputStream(InputStream inputStream, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        return new CipherInputStream(inputStream, getCipher(Cipher.DECRYPT_MODE, key));
    }

    /*
     * Returns an output stream that encrypts data using a specified secret key and initialization vector.
     */
    private static OutputStream getCipherOutputStream(OutputStream outputStream, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        return new CipherOutputStream(outputStream, getCipher(Cipher.ENCRYPT_MODE, key));
    }

    /*
     * Returns a cipher object that can be used to encrypt or decrypt data.
     */
    private static Cipher getCipher(int cipherMode, SecretKey key)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(cipherMode, key, generateIV());
        return cipher;
    }
        		
}