package me.xe_55;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class Server {
	private static final int PORT = 8888;
	private static final String KEY_ALGORITHM = "AES";
	private static final int IV_LENGTH = 16;
	private static final int SALT_LENGTH = 8;

	private static final SecureRandom SECURE_RANDOM = new SecureRandom();

	private static KeyPair keyPair;

    public static void main(String[] args) {
        try {
            // Load the X.509 certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            FileInputStream fis = new FileInputStream("server.crt");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
            fis.close();

            // Create the key pair
            keyPair = createKeyPair();

            // Create the SSL context
            String keyStoreType = KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            char[] password = "password".toCharArray();
            keyStore.load(null, password);
            keyStore.setCertificateEntry("server", cert);
            keyStore.setKeyEntry("key", keyPair.getPrivate(), password, new Certificate[]{cert});
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, password);
            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            // Create the server socket
            ServerSocket serverSocket = sslContext.getServerSocketFactory().createServerSocket(PORT);

            // Create maps for inputs/outputs
            Map<Socket, BufferedReader> inputs = new HashMap<>();
            Map<Socket, PrintWriter> outputs = new HashMap<>();

            // Wait for clients
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket.getInetAddress().getHostAddress());

                // Initialize session with client
                initSession(clientSocket, inputs, outputs);
            }

        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

	/*
	 * Initializes a session with a client.
	 */
	private static void initSession(Socket clientSocket, Map<Socket, BufferedReader> inputs, Map<Socket, PrintWriter> outputs) {
		try {
			// Create cipher streams for input and output
			BufferedReader in = new BufferedReader(new InputStreamReader(getCipherInputStream(clientSocket.getInputStream(), keyPair.getPrivate())));
			PrintWriter out = new PrintWriter(getCipherOutputStream(clientSocket.getOutputStream(), keyPair.getPrivate()), true);

			// Read and print client public key
			final byte[] receivedKeyBytes = Base64.getDecoder().decode(in.readLine());
			final PublicKey clientPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(receivedKeyBytes));
			System.out.println("Received public key from client " + clientSocket.getInetAddress().getHostAddress() + ": " + Base64.getEncoder().encodeToString(clientPublicKey.getEncoded()));

			// Generate salt and initialization vector
			final byte[] salt = generateSalt();
			final byte[] iv = generateIV();

			// Encrypt and send salt and IV to client using client public key
			final byte[] encryptedSalt = encryptWithPublicKey(salt, clientPublicKey);
			final byte[] encryptedIV = encryptWithPublicKey(iv, clientPublicKey);
			out.println(Base64.getEncoder().encodeToString(encryptedSalt));
			out.println(Base64.getEncoder().encodeToString(encryptedIV));

			// Receive session key from client and decrypt with private key
			byte[] encodedSessionKey = Base64.getDecoder().decode(in.readLine());
			PrivateKey privateKey = keyPair.getPrivate();
			byte[] decryptedSessionKey = decryptWithPrivateKey(encodedSessionKey, privateKey);
			SecretKey sessionKey = new SecretKeySpec(decryptedSessionKey, KEY_ALGORITHM);
			System.out.println("Received session key from client " + clientSocket.getInetAddress().getHostAddress());

			// Start a new thread to handle incoming messages
			new Thread(() -> {
				try {
					String inputLine;
					while ((inputLine = in.readLine()) != null) {
						// Decrypt the received message
						String decryptedMessage = decryptMessage(inputLine, sessionKey);

						// Write the decrypted message to the log file
						writeToLogFile(decryptedMessage);

						// Send the decrypted message to all clients except the sender
						for (PrintWriter outWriter : outputs.values()) {
							if (outWriter != out) {
								outWriter.println(encryptMessage(decryptedMessage, sessionKey));
							}
						}
					}
				} catch (IOException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
					e.printStackTrace();
				}
			}).start();

			// Add the input and output streams to the maps
			inputs.put(clientSocket, in);
			outputs.put(clientSocket, out);
		} catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	/*
	* Generates a random salt for key generation.
	*/
	private static byte[] generateSalt() {
	    byte[] salt = new byte[SALT_LENGTH];
	    SECURE_RANDOM.nextBytes(salt);
	    return salt;
	}

	/*
	* Generates a random initialization vector (IV) for encryption.
	*/
	private static byte[] generateIV() {
	    byte[] iv = new byte[IV_LENGTH];
	    SECURE_RANDOM.nextBytes(iv);
	    return iv;
	}

	/*
	* Generates a new RSA key pair.
	*/
	private static KeyPair createKeyPair() throws NoSuchAlgorithmException {
	    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	    keyPairGenerator.initialize(2048);
	    return keyPairGenerator.genKeyPair();
	}

	/*
	* Returns the server's public key from the X509 certificate.
	*/
	private static PublicKey getPublicKeyFromCert() throws CertificateException, IOException {
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    FileInputStream fis = new FileInputStream("server.crt");
	    X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
	    fis.close();
	    return cert.getPublicKey();
	}

	/*
	* Encrypts the given data with the specified public key.
	*/
	private static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	    return cipher.doFinal(data);
	}

	/*
	* Decrypts the given data with the server's private key.
	*/
	private static byte[] decryptWithPrivateKey(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	    Cipher cipher = Cipher.getInstance("RSA");
	    cipher.init(Cipher.DECRYPT_MODE, privateKey);
	    return cipher.doFinal(data);
	}

	/*
	* Encrypts a message with the specified session key.
	*/
	private static String encryptMessage(String message, SecretKey sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
	    byte[] iv = generateIV();
	    Cipher cipher = Cipher.getInstance(KEY_ALGORITHM + "/CBC/PKCS5Padding");
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	    cipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivParameterSpec);
	    byte[] encryptedData = cipher.doFinal(message.getBytes());
	    byte[] output = new byte[iv.length + encryptedData.length];
	    System.arraycopy(iv, 0, output, 0, iv.length);
	    System.arraycopy(encryptedData, 0, output, iv.length, encryptedData.length);
	    return Base64.getEncoder().encodeToString(output);
	}

	/*
	* Decrypts a message with the specified session key.
	*/
	private static String decryptMessage(String message, SecretKey sessionKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
	    byte[] data = Base64.getDecoder().decode(message);
	    byte[] iv = Arrays.copyOfRange(data, 0, IV_LENGTH);
	    byte[] encryptedData = Arrays.copyOfRange(data, IV_LENGTH, data.length);
	    Cipher cipher = Cipher.getInstance(KEY_ALGORITHM + "/CBC/PKCS5Padding");
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	    cipher.init(Cipher.DECRYPT_MODE, sessionKey, ivParameterSpec);
	    byte[] decryptedData = cipher.doFinal(encryptedData);
	    return new String(decryptedData);
	}

	/*
	* Returns a new CipherInputStream for the given input stream and key.
	*/
	private static CipherInputStream getCipherInputStream(InputStream inputStream, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
	    Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key);
	    return new CipherInputStream(inputStream, cipher);
	}

	/*
	* Returns a new CipherOutputStream for the given output stream and key.
	*/
	private static CipherOutputStream getCipherOutputStream(OutputStream outputStream, PrivateKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
	    Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key);
	    return new CipherOutputStream(outputStream, cipher);
	}

	/*
	* Returns a new Cipher for the given mode and key.
	*/
	private static Cipher getCipher(int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
	    Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);
	    cipher.init(mode, key);
	    return cipher;
	}

	/*
	* Writes the given string to a log file.
	*/
	private static synchronized void writeToLogFile(String message) throws IOException {
	    FileWriter fileWriter = new FileWriter("log.txt", true);
	    PrintWriter printWriter = new PrintWriter(fileWriter);
	    printWriter.println(message);
	    printWriter.close();
	}
}