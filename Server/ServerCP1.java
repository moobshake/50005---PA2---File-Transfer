import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.Base64.Encoder;
import javax.crypto.Cipher;

public class ServerCP1 {
    static final Scanner scanner = new Scanner(System.in); // scanning user input
    static ServerSocket welcomeSocket = null;
    static Socket connectionSocket = null;
    static DataOutputStream toClient = null;
    static DataInputStream fromClient = null;
    static FileOutputStream fileOutputStream = null;
    static BufferedOutputStream bufferedFileOutputStream = null;
    static String serverCert = "D:/Storage/School/SUTD/Term 5/50.005 Computer System Engineering/PA2/50005---PA2---File-Transfer/Keys/certificate_1004410.crt";
    static String nonce;
    static Key seshKey;
    static boolean verifiedClient = false;

    public static void main(String[] args) {

        int port = getPortNumber();

        while (true) { // keep the server forever running. will wait for client all the time.
            establishConnection(port);

            while (!connectionSocket.isClosed()) {
                while (!verifiedClient) {
                    System.out.println("Verifying client");
                    receiveData(); // be asked for credentials
                    System.out.println(verifiedClient);
                }
                givePerm();
                System.out.println("\nWaiting for data...");
                receiveData();

            }
        }
    }

    // receive the data from client side
    public static void receiveData() {
        try {
            int packetType = fromClient.readInt();

            System.out.println("PacketType from client: " + packetType);

            if (packetType == 0) {
                getFileName();
            } else if (packetType == 1) {
                getPackets();
            } else if (packetType == 44) {
                System.out.println("File transfer ended 1.");
            } else if (packetType == 6) {
                generateNonce();
                sendNonce();
                sendCert(serverCert);

            } else if (packetType == 4) {
                verifiedClient = checkNonce();

            } else if (packetType == 5) {
                getSeshKey();

            } else {
                System.out.println("File transfer ended 2.");
            }

        } catch (Exception exception) {
            endConnection();
            System.out.println("Client disconnected...\n\n");
        }
    }

    // receive the packets
    public static void getPackets() {
        try {
            int numBytes = fromClient.readInt();
            byte[] block = new byte[numBytes];
            fromClient.readFully(block, 0, numBytes);

            System.out.println("Bytes being read: " + numBytes);

            if (numBytes > 0)
                bufferedFileOutputStream.write(block, 0, numBytes);

            if (numBytes < 117) {
                if (bufferedFileOutputStream != null)
                    bufferedFileOutputStream.close();
                if (bufferedFileOutputStream != null)
                    fileOutputStream.close();
                System.out.println("File received.");
            }
        } catch (Exception exception) {
            System.out.println("Problem getting packets... Please try again.");
        }
    }

    // receive the filename
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

            System.out.println("File name is: " + new String(fileName, 0, numBytes));

            fileOutputStream = new FileOutputStream("recv_" + new String(fileName, 0, numBytes));
            bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            System.out.println("File name received... Getting the packets...");

        } catch (Exception exception) {
            System.out.println("Something wrong when retriving filename...");
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

    // key readers
    public static PrivateKey getPrivate() throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get("Keys/private_key.der"));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);

    }

    public static PublicKey getPublic(String filename) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /*
     * AP 1 Proves to client server is legit
     */
    public static String generateNonce() {
        /*SecureRandom rand = new SecureRandom();
        byte bytes[] = new byte[20];
        rand.nextBytes(bytes); // generates random 20 bytes
        Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String token = encoder.encodeToString(bytes);*/
        String token = "nonce";
        return token;
    }

    public static void sendCert(String certPath) {
        try {
            System.out.println("Sending Certificate");
            toClient.writeInt(3);
            toClient.writeUTF(certPath);
            toClient.flush();
            System.out.println("Certificate sent sucessfully");
        } catch (Exception e) {
            System.out.println("Certificate failed to send");
        }

    }

    public static void sendNonce() {
        try {
            nonce = generateNonce();
            System.out.println("Sending nonce");
            toClient.writeInt(2);
            toClient.writeUTF(nonce);
            toClient.flush();
            System.out.println("Nonce sent");
        } catch (Exception e) {
            System.out.println("Nonce failed to send");
        }
    }

    /*
     * AP 2 Verify client
     */

    public static boolean checkNonce() {
        boolean result = false;

        try {
            int numBytes = fromClient.readInt();
            byte[] cNonce = new byte[numBytes];
            fromClient.readFully(cNonce, 0, numBytes);
            if (cNonce.toString().equals(nonce)) {
                System.out.println("Is the nonce the same? " + (cNonce.toString().equals(nonce)));
                result = true;
            } 
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;

    }

    public static void getSeshKey() {
        try {
            int numBytes = fromClient.readInt();
            byte[] sKey = new byte[numBytes];
            fromClient.readFully(sKey, 0, numBytes);

            // get private key to decode public key
            PrivateKey privateKey = getPrivate();
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, privateKey);
            seshKey = c.unwrap(sKey, "AES/CBC/PKCS5Padding", Cipher.SECRET_KEY);
            System.out.println("Session key retrieved");
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /*
     * AP3 Tell client to start sending
     */
    public static void givePerm() {
        try {
            toClient.writeInt(10);
            toClient.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
