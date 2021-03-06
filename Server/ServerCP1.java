import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;

public class ServerCP1 {
    static final Scanner scanner = new Scanner(System.in); // scanning user input
    static ServerSocket welcomeSocket = null;
    static Socket connectionSocket = null;
    static DataOutputStream toClient = null;
    static DataInputStream fromClient = null;
    static FileOutputStream fileOutputStream = null;
    static BufferedOutputStream bufferedFileOutputStream = null;
    static PrivateKey privateKey = getPrivateKey("private_key.der");
    static PublicKey publicKey = getPublicKey("public_key.der");
    static Cipher mainCipherEN;
    static Cipher mainCipherDE;
    static int packetCount = 0;
    private static String password = "csebestmod";

    public static void main(String[] args) {

        int port = getPortNumber();

        while (true) { // keep the server forever running. will wait for client all the time.
            establishConnection(port);

            while (!connectionSocket.isClosed()) {
                System.out.println("\nWaiting for data...");
                recieveData();
            }
        }
    }

    // recieve the data from client side
    public static void recieveData() {
        try {
            int packetType = fromClient.readInt();

            System.out.println("PacketType from client: " + packetType);

            if (packetType == -44) {
                authenticateClient();
            } else if (packetType == 0) {
                getFileName();
                packetCount = 0;
            } else if (packetType == 1) {
                getPackets();
            } else if (packetType == 44) {
                System.out.println("Client ended connection...");
                endConnection();
            } else {
                System.out.println("Unknown packetType...");
            }

        } catch (Exception exception) {
            endConnection();
            System.out.println("Something went wrong... Client disconnected...\n\n");
        }
    }

    // recieve the packets
    public static void getPackets() {
        try {
            

            int encryptedNumBytes = fromClient.readInt();
            byte[] encryptedBlock = new byte[encryptedNumBytes];
            fromClient.readFully(encryptedBlock, 0, encryptedNumBytes);

            byte[] decryptedData = decryptData(encryptedBlock);

            packetCount++;
            System.out.println("This is packetCount: " + packetCount);

            if (decryptedData.length > 0)
                bufferedFileOutputStream.write(decryptedData, 0, decryptedData.length);

            if (decryptedData.length < 245) {
                if (bufferedFileOutputStream != null)
                    bufferedFileOutputStream.close();
                if (bufferedFileOutputStream != null)
                    fileOutputStream.close();
                System.out.println("\nFile succesffuly recieved. Can transfer new files.");
                toClient.writeInt(33);
            }
        } catch (Exception exception) {
            System.out.println("Problem getting packets... Please try again.");
        }
    }

    // recieve the filename
    public static void getFileName() {
        try {
            System.out.println("Getting file name...");

            int numBytes = fromClient.readInt();
            System.out.println("The number of bytes for filename is: " + numBytes);
            byte[] fileName = new byte[numBytes];
            // Must use read fully!
            // See:
            // https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
            fromClient.readFully(fileName, 0, numBytes);

            byte[] decryptedData = decryptData(fileName);

            System.out.println("File name is: " + new String(decryptedData, 0, decryptedData.length) + " with length: " + decryptedData.length);

            fileOutputStream = new FileOutputStream("recv_" + new String(decryptedData, 0, decryptedData.length));
            bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            System.out.println("File name recieved... Getting the packets...");

        } catch (Exception exception) {
            System.out.println("Something wrong when retriving filename...");
        }
    }

    // decrypt data
    public static byte[] decryptData(byte[] encryptedData) {
        try {
			System.out.println("Decrypting data received...");
            System.out.println("Encrypted data of length: " + encryptedData.length);
            byte[] decryptedData = mainCipherDE.doFinal(encryptedData);
            System.out.println("Successfully decrypted data.");
            System.out.println("Decrypted data of length: " + decryptedData.length);
			return decryptedData;
		} catch (Exception exception) {
			System.out.println("Something went wrong with the encryption...");
			return null;
		}
    }

    // end connection
    public static void endConnection() {
        try {
            System.out.println("Ending connection with client...");
            connectionSocket.close();
            System.out.println("Ended connection with client.\n\n");
        } catch (Exception exception) {
            System.out.println("Connection already closed.");
        }
    }

    // check if port can be used
    public static boolean checkPort(int port) {
        try {
            System.out.println("Checking if port can be used...");
            welcomeSocket = new ServerSocket(port);
            System.out.println("Port can be used!");
            return true;
        } catch (Exception exception) {
            System.out.println("Port cannot be used... Please choose another port.");
            return false;
        }
    }

    // establish connection
    public static void establishConnection(int port) {
        try {
            System.out.println("Waiting for client to connect...");
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            System.out.println("Client connected!");
        } catch (Exception exception) {
            System.out.println("Something went wrong with establishing the connection... Try running client again...");
        }
    }

    // authentication for client.
    public static void authenticateClient() {
        try {
            System.out.println("Starting authentication with client");

            // random number generator for
			Random random = new Random(System.currentTimeMillis());
			int nonce = random.nextInt(100000);

            System.out.println("Generated NONCE value of: " + nonce + ". Encrypting this nonce now...");

            mainCipherDE = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			mainCipherDE.init(Cipher.DECRYPT_MODE, privateKey);

            mainCipherEN = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			mainCipherEN.init(Cipher.ENCRYPT_MODE, privateKey);


            // encrypt nonce
            byte[] nonceByte = ByteBuffer.allocate(4).putInt(nonce).array();
            byte[] encryptedNONCE = mainCipherEN.doFinal(nonceByte);
            System.out.println("Nonce encrypted and sending to client...");

            // send encrypted nonce
            toClient.writeInt(encryptedNONCE.length);
            toClient.write(encryptedNONCE);
            toClient.flush();
            System.out.println("Encrypted nonce sent to client. Sending certificate now.");

            String certificateString = "certificate_1004152.crt";

            System.out.println("Sending signed certificate filename...");
            toClient.writeInt(certificateString.getBytes().length);
			toClient.write(certificateString.getBytes());
			toClient.flush();
            System.out.println("Signed certificate filename sent... Sending certificate file now...");
            FileInputStream fileInputStream = new FileInputStream(certificateString);
            BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            int count;
            byte[] Buffer = new byte[1023];
            while ((count = bufferedFileInputStream.read(Buffer)) > 0) {
                toClient.write(Buffer, 0, count);
                toClient.flush();
            }

            bufferedFileInputStream.close();
            fileInputStream.close();

            System.out.println("Certificate sent. Hopefully Client will be legit!");

            // recieve encrypted nonce
            int numBytesPublic = fromClient.readInt();
            byte[] encryptedNoncePublic = new byte[numBytesPublic];
            fromClient.readFully(encryptedNoncePublic, 0, numBytesPublic);
            System.out.println("Recieved encrypted Nonce Value. Decrypting with private key and checking...");

			byte[] decryptedNONCE = mainCipherDE.doFinal(encryptedNoncePublic);
			int verifyNonce = ByteBuffer.wrap(decryptedNONCE).getInt();
            System.out.println("Decrypted NONCE is: " + verifyNonce);

            if (verifyNonce == nonce) {
                toClient.writeInt(88);
                System.out.println("Nonce matches. Client is live.\n");
                tellClientLive();
            } else {
                toClient.writeInt(55);
                System.out.println("Nonce doesn't match. Client is not live.");
                endConnection();
            }

        } catch (Exception exception) {
            System.out.println("Something wrong with authentication...");
        }
    }

    // to tell the client that server is live
	public static void tellClientLive() {
        try {
            // recieve encrypted nonce
			int numBytes = fromClient.readInt();
			byte[] encryptedNonce = new byte[numBytes];
			fromClient.readFully(encryptedNonce, 0, numBytes);
			System.out.println("Recieved encrypted Nonce Value. Decrypting the nonce...");

            byte[] decryptedNONCE = mainCipherDE.doFinal(encryptedNonce);
			int decryptedNONCEInt = ByteBuffer.wrap(decryptedNONCE).getInt();

			System.out.println("Decrypted NONCE is: " + decryptedNONCEInt);

            // encrypt nonce with public key top send back
			System.out.println("Encrypting NONCE with private key to send back to client...");
			byte[] encryptedNoncePrivate = ByteBuffer.allocate(4).putInt(decryptedNONCEInt).array();
			byte[] encryptedNoncePrivateSending = mainCipherEN.doFinal(encryptedNoncePrivate);
			System.out.println("Nonce encrypted and sending back to client...");

            // send encrypted nonce
            toClient.writeInt(encryptedNoncePrivateSending.length);
            toClient.write(encryptedNoncePrivateSending);
            toClient.flush();
            System.out.println("Encrypted nonce with private key sent to client. Waiting for confirmation from client...");

            int clientAccept = fromClient.readInt();
			if (clientAccept == 88) {
				System.out.println("Client accepted connection!\n");
                checkPassword();
			} else if (clientAccept == 55) {
				System.out.println("Client did not accept connection...");
				endConnection();
			}
        }
        catch (Exception exception) {
            System.out.println("Something went wrong decrypting nonce from client...");
        }
 	}

    // tell client to send password to authenticate if user is real
    public static void checkPassword() {
        try {
            System.out.println("Waiting for client to send password over...\n");

            int numBytes = fromClient.readInt();
            byte[] clientPassword = new byte[numBytes];
            fromClient.readFully(clientPassword, 0, numBytes);
            System.out.println("Encrypted password recieved. Checking...");
            System.out.println("Decrypting password with private key... ");
            byte[] decryptedData = mainCipherDE.doFinal(clientPassword);
            String clientPasswordDecryted = new String(decryptedData);
            System.out.println("Password decrypted... Client entered: " + clientPasswordDecryted);

            if (clientPasswordDecryted.equals(password)) {
                System.out.println("Client entered correct password. Is authenticated!\n");
                toClient.writeInt(111);
            } else {
                toClient.writeInt(222);
                System.out.println("Client entered incorrect password. Gonna yeet before client sends anything else...");
                endConnection();
            }
		}
		catch (Exception exception) {
			System.out.println("\nPassword is wrong! Client have no access...\n");
			endConnection();
        }
    }

    // read the private key
    public static PrivateKey getPrivateKey(String fileName) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception exception) {
            System.out.println("Cannot get private key...");
            return null;
        }
    }

    // read the public key
    public static PublicKey getPublicKey(String filename) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception exception) {
            System.out.println("Cannot get public key...");
            return null;
        }
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
                valid = checkPort(port);
                break; // use default 44444
            }
            try {
                Integer tempInteger = Integer.parseInt(scanned);
                if (tempInteger >= 0 && tempInteger < 65353) {
                    port = tempInteger;
                    System.out.println("Using port number " + port + " for connection.");
                    valid = checkPort(port);
                } else {
                    System.out.println("Invalid port number. Please enter a port number between 0 to 65353...");
                }
            } catch (Exception exception) {
                System.out.println("Invalid input! Please enter a port NUMBER between 0 to 65353...");
            }
        }
        return port;
    }
}