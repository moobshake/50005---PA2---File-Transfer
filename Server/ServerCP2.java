import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {
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
            } else if (packetType == 22) {
                sessionKeyRec();
            } else if (packetType == 44) {
                System.out.println("Client ended connection...");
                endConnection();
            } else if (packetType == 1002) {
                System.out.println("\nClient wants to get the filenames in server");
                sendFileNamesInServer();
            } else if (packetType == 1003) {
                System.out.println("\nClient wants to download file from server");
                downloadFile();
            } else if (packetType == 1004) {
                System.out.println("\nClient wants to delete file from server");
                deleteFile();
            } else {
                System.out.println("Unknown packetType...");
            }

        } catch (Exception exception) {
            endConnection();
            System.out.println("Something went wrong... Client disconnected...\n\n");
        }
    }

    // send to client the filenames that are in server
    public static void sendFileNamesInServer() {
        try {
            sessionKeyRec();

            File folder = new File(".");
            File[] listOfFiles = folder.listFiles();

            ArrayList<String> arrayListOfFileName = new ArrayList<String>();

            for (int i = 0; i < listOfFiles.length; i++) {
                if (listOfFiles[i].isFile()) {
                    if (!listOfFiles[i].getName().equals("ServerCP1.java")
                            && !listOfFiles[i].getName().equals("ServerCP2.java")
                            && !listOfFiles[i].getName().equals("public_key.der")
                            && !listOfFiles[i].getName().equals("private_key.der")
                            && !listOfFiles[i].getName().equals("certificate_1004152.crt")) {
                        arrayListOfFileName.add(listOfFiles[i].getName());
                    }
                }
            }

            if (arrayListOfFileName.size() == 0) {
                System.out.println("There are no files currently in server that can be sent...");
                toClient.writeInt(1010);
            } else {
                System.out.println("There are files currently in server that can be sent...");
                toClient.writeInt(1011);

                for (String fileString : arrayListOfFileName) {
                    System.out.println("Sending filename '" + fileString + "'...");

                    toClient.writeInt(1009);

                    System.out.println("Filename bytes: " + fileString.getBytes().length);
                    System.out.println("Encrypting data to be sent...");
                    byte[] encryptedFileName = mainCipherEncrypt.doFinal(fileString.getBytes());
                    System.out.println("Encrypted data. Sending...");
                    toClient.writeInt(encryptedFileName.length);
                    toClient.write(encryptedFileName);
                    toClient.flush();
                }

                System.out.println("Filenames sent...");
                toClient.writeInt(1008);
            }
        } catch (Exception exception) {
            System.out.println("Something went wrong getting filenames from server...");
        }
    }

    // client wants to download file
    public static void downloadFile() {
        try {
            sessionKeyRec();

            System.out.println("Getting file name...");

            int numBytes = fromClient.readInt();
            byte[] fileName = new byte[numBytes];
            fromClient.readFully(fileName, 0, numBytes);

            byte[] decryptedData = decryptData(fileName);

            String fileNameDecrypted = new String(decryptedData);

            System.out.println("File name is: " + new String(decryptedData, 0, decryptedData.length) + " with length: "
                    + decryptedData.length);

            File file = new File(fileNameDecrypted);
            if (file.exists()) {
                System.out.println("File exist in server. Sending...");
                toClient.writeInt(1013);
                // Open the file
                FileInputStream fileInputStream = new FileInputStream(fileNameDecrypted);
                BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);
                int packetCount = 0;
                byte[] fromFileBuffer = new byte[245];

                // Send the file
                for (boolean fileEnded = false; !fileEnded;) {
                    numBytes = bufferedFileInputStream.read(fromFileBuffer);
                    fileEnded = numBytes < 245;
                    System.out.println("\nBytes being written BEFORE encryption: " + numBytes);

                    // if last packet means there will be less than 245 bytes thus need to
                    // limit the number of bytes.
                    byte[] encryptedData;
                    if (fileEnded) {
                        byte[] lastPacket = Arrays.copyOf(fromFileBuffer, numBytes);
                        encryptedData = mainCipherEncrypt.doFinal(lastPacket);
                    } else {
                        encryptedData = mainCipherEncrypt.doFinal(fromFileBuffer);
                    }

                    System.out.println("Bytes being written AFTER encryption: " + encryptedData.length);
                    packetCount++;
                    System.out.println("This is packetCount: " + packetCount);

                    toClient.writeInt(1);
                    toClient.writeInt(encryptedData.length);
                    toClient.write(encryptedData, 0, encryptedData.length);
                    toClient.flush();
                }

                toClient.writeInt(999);
                fileInputStream.close();
                bufferedFileInputStream.close();
                System.out.println("Waiting for client to confirm receipt of file...");
                int confirmation = fromClient.readInt();

                if (confirmation == 998) {
                    System.out.println("Client succesfully received file.");
                } else {
                    System.out.println("Client says files not receieved properly.");
                }

            } else {
                System.out.println("File does not exist in server... Nothing was deleted.");
                toClient.writeInt(1012);
            }

        } catch (Exception exception) {
            System.out.println("Something went wrong deleting file... Ending connection with client...");
            endConnection();
        }
    }

    // client wants to delete file
    public static void deleteFile() {
        try {
            sessionKeyRec();

            System.out.println("Getting file name...");

            int numBytes = fromClient.readInt();
            byte[] fileName = new byte[numBytes];
            fromClient.readFully(fileName, 0, numBytes);

            byte[] decryptedData = decryptData(fileName);

            String fileNameDecrypted = new String(decryptedData);

            System.out.println("File name is: " + new String(decryptedData, 0, decryptedData.length) + " with length: "
                    + decryptedData.length);

            File file = new File(fileNameDecrypted);
            if (file.exists()) {
                System.out.println("File exist in server. Deleting...");
                file.delete();
                toClient.writeInt(1015);
            } else {
                System.out.println("File does not exist in server... Nothing was deleted.");
                toClient.writeInt(1014);
            }

        } catch (Exception exception) {
            System.out.println("Something went wrong deleting file... Ending connection with client...");
            endConnection();
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

            System.out.println("File name is: " + new String(decryptedData, 0, decryptedData.length) + " with length: "
                    + decryptedData.length);

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
        } catch (Exception exception) {
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
                System.out.println("Nonce matches. Client is live.");
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

    // tell client that server is live
    public static void tellClientLive() {
        try {
            System.out.println("\nClient going to check if Sever is live...");
            sessionKeyRec();
            // recieve encrypted nonce
            int numBytes = fromClient.readInt();
            byte[] encryptedNonce = new byte[numBytes];
            fromClient.readFully(encryptedNonce, 0, numBytes);
            System.out.println("Recieved encrypted Nonce Value. Using session key to decrypt...");

            byte[] decryptedNONCE = mainCipherDecrypt.doFinal(encryptedNonce);
            int decryptedNONCEInt = ByteBuffer.wrap(decryptedNONCE).getInt();

            System.out.println("Decrypted NONCE is: " + decryptedNONCEInt + ". Encrypting this with private key...");

            // encrypt nonce
            byte[] nonceByte = ByteBuffer.allocate(4).putInt(decryptedNONCEInt).array();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] encryptedNONCE = cipher.doFinal(nonceByte);
            System.out.println("Nonce encrypted and sending to client...");

            // send encrypted nonce
            toClient.writeInt(encryptedNONCE.length);
            toClient.write(encryptedNONCE);
            toClient.flush();
            System.out.println("Encrypted nonce sent to client. Waiting for client's reply...");

            int serverAccept = fromClient.readInt();
            if (serverAccept == 88) {
                System.out.println("Client accepted connection!");
                // checkPassword();
            } else if (serverAccept == 55) {
                System.out.println("Client did not accept connection...");
                endConnection();
            }
        } catch (Exception exception) {
            System.out.println("Client did not think that server is live...");
            endConnection();
        }
    }

    // sending password to authenticate client
    public static void checkPassword() {
        try {
            System.out.println("\nGenerating password session key...");
            // Generate session key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128);
            SecretKey passwordKey = keyGenerator.generateKey();
            Cipher oneTimeCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            oneTimeCipher.init(Cipher.DECRYPT_MODE, passwordKey);
            System.out.println("Password Session key generated.");

            // send encrypted session key with public key
            System.out.println("Sending encrypted password session key with private key...");
            Cipher enCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            enCipher.init(Cipher.ENCRYPT_MODE, privateKey);

            byte[] encryptPasswordKey = enCipher.doFinal(passwordKey.getEncoded());
            toClient.writeInt(encryptPasswordKey.length);
            toClient.write(encryptPasswordKey);
            toClient.flush();
            System.out.println("Encrypted password session key sent. Waiting for password to be sent over...\n");

            int numBytes = fromClient.readInt();
            byte[] clientPassword = new byte[numBytes];
            fromClient.readFully(clientPassword, 0, numBytes);
            System.out.println("Encrypted password recieved. Checking...");

            System.out.println("Decrypting password with password session key... ");
            byte[] decryptedData = oneTimeCipher.doFinal(clientPassword);
            String clientPasswordDecryted = new String(decryptedData);
            System.out.println("Password decrypted... Client entered: " + clientPasswordDecryted);

            if (clientPasswordDecryted.equals(password)) {
                System.out.println("Client entered correct password. Is authenticated!\n");
                toClient.writeInt(111);
            } else {
                toClient.writeInt(222);
                System.out
                        .println("Client entered incorrect password. Gonna yeet before client sends anything else...");
                endConnection();
            }
        } catch (Exception exception) {
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