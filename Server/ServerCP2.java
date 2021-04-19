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
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
    static int packetCount = 0;
    static Cipher mainCipherEncrypt;
	static Cipher mainCipherDecrypt;
	static SecretKey sessionKey;

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
            } else if (packetType == 22) {
                sessionKeyRec();
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
                System.out.println("\nFile has been succesfully recieved. Can transfer new files.");
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
            byte[] decryptedData = mainCipherDecrypt.doFinal(encryptedData);
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

    // recieve session key from client 
    public static void sessionKeyRec() {
        try {
            // recieve encrypted session key
            int encryptedSessionKeyLength = fromClient.readInt();
            byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
            fromClient.readFully(encryptedSessionKey, 0, encryptedSessionKeyLength);
            System.out.println("\nRecieved encrypted session key.");

            // decrypt session key
            System.out.println("Decrypting to get session key...");
            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            deCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSessionKey = deCipher.doFinal(encryptedSessionKey);
            sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
            mainCipherEncrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherEncrypt.init(Cipher.ENCRYPT_MODE, sessionKey);
			mainCipherDecrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey);
            System.out.println("Session key decrypted. Using session key to decrypt data...");
        }
        catch (Exception exception) {
            System.out.println("Something wrong when recieving session key...");
            endConnection();
        }
    }

    // authentication for client.
    public static void authenticateClient() {
        try {
            System.out.println("Starting authentication with client...");

            // random number generator for
			Random random = new Random(System.currentTimeMillis());
			int nonce = random.nextInt(100000);

            System.out.println("Generated NONCE value of: " + nonce + ". Encrypting this nonce now...");

            // encrypt nonce
            byte[] nonceByte = ByteBuffer.allocate(4).putInt(nonce).array();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedNONCE = cipher.doFinal(nonceByte);
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
            System.out.println("Recieved encrypted Nonce Value.");

            // recieve encrypted session key
            int encryptedSessionKeyLength = fromClient.readInt();
            byte[] encryptedSessionKey = new byte[encryptedSessionKeyLength];
            fromClient.readFully(encryptedSessionKey, 0, encryptedSessionKeyLength);
            System.out.println("Recieved encrypted session key.");

            // decrypt session key
            System.out.println("Decrypting to get session key...");
            Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            deCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSessionKey = deCipher.doFinal(encryptedSessionKey);
            sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
            mainCipherEncrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherEncrypt.init(Cipher.ENCRYPT_MODE, sessionKey);
			mainCipherDecrypt = Cipher.getInstance("AES/ECB/PKCS5Padding");
			mainCipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey);
            System.out.println("Session key decrypted. Decrypting nonce with session key...");
            
			byte[] decryptedNONCE = mainCipherDecrypt.doFinal(encryptedNoncePublic);
			int verifyNonce = ByteBuffer.wrap(decryptedNONCE).getInt();
            System.out.println("Decrypted NONCE is: " + verifyNonce);

            if (verifyNonce == nonce) {
                toClient.writeInt(88);
                System.out.println("Nonce matches. Client is authenticated.");
            } else {
                toClient.writeInt(55);
                System.out.println("Nonce doesn't match. Client is not authenticated.");
                endConnection();
            }

        } catch (Exception exception) {
            System.out.println("Something wrong with authentication...");
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