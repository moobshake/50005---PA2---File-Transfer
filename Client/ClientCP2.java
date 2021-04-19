import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ClientCP2 {

	static final Scanner scanner = new Scanner(System.in); // scanning user input
	static Socket clientSocket = null;
	static DataOutputStream toServer = null;
	static DataInputStream fromServer = null;
	static FileInputStream fileInputStream = null;
	static BufferedInputStream bufferedFileInputStream = null;
	static String signedCertificateString = "";
	static PublicKey publicKey;
	static Cipher mainCipherEncrypt;
	static Cipher mainCipherDecrypt;
	static SecretKey sessionKey;

	public static void main(String[] args) {

		String serverAddress = getAddress();
		int port = getPortNumber();
		String fileName = "";

		while (!establishConnection(port, serverAddress)) {
			serverAddress = getAddress();
			port = getPortNumber();
		}

		while (!clientSocket.isClosed()) {
			fileName = getFileName();
			if (fileName == "") {
				endConnection(); // close connection and end program
				break;
			}
			sendFileName(fileName);
			sendPackets(fileName);
		}

		System.out.println("Program ended.");
	}

	// send data of file
	public static void sendPackets(String fileName) {
		try {
			// Open the file
			fileInputStream = new FileInputStream(fileName);
			bufferedFileInputStream = new BufferedInputStream(fileInputStream);

			int packetCount = 0;

			int totalBytes = 0;
			long startTime = System.currentTimeMillis();

			int numBytes = 0;
			byte[] fromFileBuffer = new byte[245];

			// Send the file
			for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 245;
				System.out.println("\nBytes being written BEFORE encryption: " + numBytes);
				totalBytes += numBytes;

				// if last packet means there will be less than 245 bytes thus need to
				// limit the number of bytes.
				byte[] encryptedData;
				if (fileEnded) {
					byte[] lastPacket = Arrays.copyOf(fromFileBuffer, numBytes);
					encryptedData = encryptData(lastPacket);
				} else {
					encryptedData = encryptData(fromFileBuffer);
				}

				System.out.println("Bytes being written AFTER encryption: " + encryptedData.length);
				packetCount++;
				System.out.println("This is packetCount: " + packetCount);

				toServer.writeInt(1);
				toServer.writeInt(encryptedData.length);
				toServer.write(encryptedData, 0, encryptedData.length);
				toServer.flush();
			}

			fileInputStream.close();
			bufferedFileInputStream.close();

			System.out.println("Finish uploading data.");

			System.out.println("Waiting for confirmation that server has recieved data.");

			int confirmation = fromServer.readInt();
			double endTime = (double) (System.currentTimeMillis() - startTime) / (double)1000;

			if (confirmation == 33) {
				System.out.println("\nServer has successfully recieved data.");
				String message = "Sent file, " + fileName + ", of size " + totalBytes + " bytes, took " + endTime + " seconds.";
				System.out.println(message);
				// write to file. so can look back and see see
				Writer writer = new BufferedWriter(new FileWriter("logsCP2.txt", true));
				writer.append(message + "\n");
				writer.close();
			} else {
				System.out.println("Server did not respond correctly, something went wrong...");
			}

		} catch (Exception exception) {
			System.out.println("Something wrong with sending the packets... Please try again!");
		}

	}

	// send filename
	public static void sendFileName(String fileName) {
		try {
			// generate and send session key first
			sessionKeyGen(true);

			System.out.println("Sending filename '" + fileName + "'...");

			// Send the filename
			toServer.writeInt(0);

			System.out.println("Filename bytes: " + fileName.getBytes().length);
			byte[] encryptedFileName = encryptData(fileName.getBytes());
			
			toServer.writeInt(encryptedFileName.length);
			toServer.write(encryptedFileName);
			toServer.flush();

			System.out.println("File name sent successfully!");
		} catch (Exception exception) {
			System.out.println("Cannot transfer file... Please try again.");
		}
	}

	// encryption algorithm 
	public static byte[] encryptData(byte[] data) {
		try {
			System.out.println("Encrypting data to be sent...");
			byte[] encryptedData = mainCipherEncrypt.doFinal(data);
			System.out.println("Encrypted data. Sending...");
			return encryptedData;
		} catch (Exception exception) {
			System.out.println("Something went wrong with the encryption...");
			return null;
		}
	}

	// end connection and end program.
	public static void endConnection() {
		System.out.println("Closing connection...");
		try {
			toServer.writeInt(44);
			clientSocket.close();
			System.out.println("Connection closed.");
			System.exit(0);
		} catch (Exception exception) {
			System.out.println("Connection already closed.");
			System.exit(0);
		}
	}

	// establish connection
	public static boolean establishConnection(int port, String serverAddress) {
		try {
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			authenticateServer();
			return true;
		} catch (Exception e) {
			System.out.println("Cannot establish connection. Please check address and port.");
			return false;
		}
	}

	// generate and send session key
	public static void sessionKeyGen(boolean newFile) {
		try {
			System.out.println("\nGenerating session key...");
			// Generate session key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			sessionKey = keyGenerator.generateKey();
			mainCipherEncrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherEncrypt.init(Cipher.ENCRYPT_MODE, sessionKey);
			mainCipherDecrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey);
			System.out.println("Session key generated.");

			// send encrypted session key with public key
			System.out.println("Sending encrypted session key with public key...");
			Cipher enCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			enCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			if (newFile){
				toServer.writeInt(22);
			}
			byte[] encryptSessionKey = enCipher.doFinal(sessionKey.getEncoded());
            toServer.writeInt(encryptSessionKey.length);
            toServer.write(encryptSessionKey);
            toServer.flush();
            System.out.println("Encrypted session key sent.\n");
		}
		catch (Exception exception) {
			System.out.println("\nSomething went wrong sending session key...\n");
			endConnection();
		}
	}

	// authenticate the server
	public static void authenticateServer() {
		try {
			System.out.println("\nStarting authentication...");
			// tell server to authenticate
			toServer.writeInt(-44);

			// recieve encrypted nonce
			int numBytes = fromServer.readInt();
			byte[] encryptedNonce = new byte[numBytes];
			fromServer.readFully(encryptedNonce, 0, numBytes);
			System.out.println("Recieved encrypted Nonce Value. Getting Certificate...");

			// getting certificate
			numBytes = fromServer.readInt();
			byte[] filename = new byte[numBytes];
			fromServer.readFully(filename, 0, numBytes);
			String filenameString = new String(filename, 0, numBytes);
			System.out.println("Filename recieved is: " + filenameString + ". Receiving cert now...");
			signedCertificateString = "recv_" + filenameString;

			FileOutputStream fileOutputStream = new FileOutputStream(signedCertificateString);
			BufferedOutputStream bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

			byte[] Buffer = new byte[1023];
			int count;
			while ((count = fromServer.read(Buffer)) > 0) {
				bufferedFileOutputStream.write(Buffer, 0, count);
				if (count < 1023) {
					break;
				}
			}

			bufferedFileOutputStream.close();
			fileOutputStream.close();

			System.out.println("Recieved Certificate. Checking...");

			InputStream caCertFile = new FileInputStream("cacsertificate.crt");
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(caCertFile);
			PublicKey caKey = caCert.getPublicKey();

			InputStream signedCertFile = new FileInputStream(signedCertificateString);
			X509Certificate signedCert = (X509Certificate) certificateFactory.generateCertificate(signedCertFile);
			signedCert.checkValidity();
			signedCert.verify(caKey);

			publicKey = signedCert.getPublicKey();

			System.out.println("Generating session key...");
			// Generate session key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			sessionKey = keyGenerator.generateKey();
			mainCipherEncrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherEncrypt.init(Cipher.ENCRYPT_MODE, sessionKey);
			mainCipherDecrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey);
			System.out.println("Session key generated.");

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			byte[] decryptedNONCE = cipher.doFinal(encryptedNonce);
			int decryptedNONCEInt = ByteBuffer.wrap(decryptedNONCE).getInt();

			System.out.println("Decrypted NONCE is: " + decryptedNONCEInt);

			// encrypt nonce with session key top send back
			System.out.println("Encrypting NONCE with session key to send back to server...");
			byte[] encryptedNonceSession = ByteBuffer.allocate(4).putInt(decryptedNONCEInt).array();
			byte[] encryptedNonceSessionSending = mainCipherEncrypt.doFinal(encryptedNonceSession);
			System.out.println("Nonce encrypted and sending back to server...");

			// send encrypted nonce
            toServer.writeInt(encryptedNonceSessionSending.length);
            toServer.write(encryptedNonceSessionSending);
            toServer.flush();
            System.out.println("Encrypted nonce with session key sent to client.");

			// send encrypted session key with public key
			System.out.println("Sending encrypted session key with public key...");
			Cipher enCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			enCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptSessionKey = enCipher.doFinal(sessionKey.getEncoded());
            toServer.writeInt(encryptSessionKey.length);
            toServer.write(encryptSessionKey);
            toServer.flush();
            System.out.println("Encrypted session key sent. Waiting for confirmation...");
			
			int serverAccept = fromServer.readInt();
			if (serverAccept == 88) {
				System.out.println("Server accepted connection!");
				checkServerLive();
			} else if (serverAccept == 55) {
				System.out.println("Server did not accept connection...");
				endConnection();
			}


		} catch (Exception exception) {
			System.out.println("Something went wrong with authenticating the server... Prolly something wrong with certificate.");
			endConnection();
		}
	}

	// check if server is live
	public static void checkServerLive() {
		try {
			System.out.println("\nChecking server is live...");
			// random number generator for
			Random random = new Random(System.currentTimeMillis());
			int nonce = random.nextInt(100000);

            System.out.println("Generated NONCE value of: " + nonce + ". Encrypting this nonce now...");
			sessionKeyGen(false);
			byte[] encryptedNonceSession = ByteBuffer.allocate(4).putInt(nonce).array();
			byte[] encryptedNonceSessionSending = mainCipherEncrypt.doFinal(encryptedNonceSession);
			toServer.writeInt(encryptedNonceSessionSending.length);
            toServer.write(encryptedNonceSessionSending);
            toServer.flush();
            System.out.println("Encrypted nonce with session key sent to server.");

			System.out.println("Waiting for nonce encrypted with server private key to be sent back...");

			// recieve encrypted nonce
			int numBytes = fromServer.readInt();
			byte[] encryptedNonce = new byte[numBytes];
			fromServer.readFully(encryptedNonce, 0, numBytes);
			System.out.println("Recieved encrypted Nonce Value. Decrypting with public key and checking if server is live...");

			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			byte[] decryptedNONCE = cipher.doFinal(encryptedNonce);
			int decryptedNONCEInt = ByteBuffer.wrap(decryptedNONCE).getInt();

			if (decryptedNONCEInt == nonce) {
				toServer.writeInt(88);
                System.out.println("Nonce matches. Server is live.");
				sendPassword();
            } else {
                toServer.writeInt(55);
                System.out.println("Nonce doesn't match. Server is not live.");
                endConnection();
            }

		}
		catch (Exception exception) {
			System.out.println("Server is not live...");
			endConnection();
		}
	}

	// sending password to authenticate client
	public static void sendPassword() {
		try {
            // recieve encrypted session key
            int encryptedSessionKeyLength = fromServer.readInt();
            byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
            fromServer.readFully(encryptedSessionKey, 0, encryptedSessionKeyLength);
            System.out.println("\nRecieved encrypted password session key.");

            // decrypt session key
            System.out.println("Decrypting to get password session key with public key...");
            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            deCipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] decryptedSessionKey = deCipher.doFinal(encryptedSessionKey);
            SecretKey passwordSessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
            System.out.println("Password Session key decrypted. Using password session key to encrypt password...");

			System.out.print("\nPlease enter password to have access to the server: ");
			String password = scanner.nextLine();
			System.out.println("Encrypting password with password session key...");
			Cipher passwordCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			passwordCipher.init(Cipher.ENCRYPT_MODE, passwordSessionKey);

			byte[] encryptedPassword = passwordCipher.doFinal(password.getBytes());
			System.out.println("Password encrypted. Sending to server now...");
			
			toServer.writeInt(encryptedPassword.length);
			toServer.write(encryptedPassword);
			toServer.flush();

			System.out.println("\nPassword sent to sever. Waiting for sever to authenticate...");

			int serverAccept = fromServer.readInt();
			if (serverAccept == 111) {
				System.out.println("Server accepted password. Can begin sending data!");
			} else if (serverAccept == 222) {
				System.out.println("Server did not accept connection... WRONG PASSWORD...");
				endConnection();
			}

        }
        catch (Exception exception) {
            System.out.println("Something wrong when recieving session key...");
            endConnection();
        }
	}

	// get address. will default to 'localhost' if nothing is entered
	public static String getAddress() {
		String address = "localhost";

		System.out.print("Please enter address that you want to use (press enter to use default 'localhost'): ");

		String scanned = scanner.nextLine();

		if (scanned == "") {
			System.out.println("Using default 'localhost' for file transfer.");
		} else {
			address = scanned;
			System.out.println("Using location '" + address + "' for connection.");
		}

		return address;
	}

	// get port number. will default to 44444 if nothing is entered.
	public static int getPortNumber() {
		Integer port = 44444;
		boolean valid = false;

		while (!valid) {
			System.out.print(
					"Please enter port number that you want to use (press enter to use default port of '44444'): ");

			String scanned = scanner.nextLine();

			if (scanned == "") {
				System.out.println("Using default port number 44444 for file transfer.");
				break; // use default 44444
			}

			try {
				Integer tempInteger = Integer.parseInt(scanned);
				if (tempInteger >= 0 && tempInteger < 65353) {
					port = tempInteger;
					System.out.println("Using port number " + port + " for connection.");
					valid = true;
				} else {
					System.out.println("Invalid port number. Please enter a port number between 0 to 65353...");
				}
			} catch (Exception exception) {
				System.out.println("Invalid input! Please enter a port NUMBER between 0 to 65353...");
			}
		}

		return port;
	}

	// to get user input on what file they want to send and check whether it exists
	// first
	public static String getFileName() {

		boolean exist = false; // check if file exist
		String fileName = ""; // stores the filename

		while (!exist) {
			System.out.print("\nPlease enter filename that you want to send (press enter to quit): ");

			fileName = scanner.nextLine();

			if (fileName == "")
				break;

			System.out.println("Checking if file, " + fileName + ", exists in current directory...");

			File file = new File(fileName);

			if (file.exists() && !file.isDirectory()) {
				System.out.println("Found file!");

				exist = true;
			} else {
				System.out.println(
						"File not found. Please enter a valid file name and ensure that file is in current directory!");
			}
		}

		return fileName;
	}
}