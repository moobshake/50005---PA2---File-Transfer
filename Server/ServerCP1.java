import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;
import java.util.concurrent.locks.Lock;

public class ServerCP1 {
    static final Scanner scanner = new Scanner(System.in); // scanning user input
    static ServerSocket welcomeSocket = null;
    static Socket connectionSocket = null;
    static DataOutputStream toClient = null;
    static DataInputStream fromClient = null;
    static FileOutputStream fileOutputStream = null;
    static BufferedOutputStream bufferedFileOutputStream = null;

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

            if (packetType == 0) {
                getFileName();
            } else if (packetType == 1) {
                getPackets();
            } else if (packetType == 44) {
                System.out.println("File transfer ended 1.");
            } else {
                System.out.println("File transfer ended 2.");
            }

        } catch (Exception exception) {
            endConnection();
            System.out.println("Client disconnected...\n\n");
        }
    }

    // recieve the packets
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
                System.out.println("File recieved.");
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

            System.out.println("File name is: " + new String(fileName, 0, numBytes));

            fileOutputStream = new FileOutputStream("recv_" + new String(fileName, 0, numBytes));
            bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            System.out.println("File name recieved... Getting the packets...");

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
}