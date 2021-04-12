import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.Scanner;

public class ClientCP1 {

	static final Scanner scanner = new Scanner(System.in); // scanning user input
	static Socket clientSocket = null;
	static DataOutputStream toServer = null;
	static DataInputStream fromServer = null;
	static FileInputStream fileInputStream = null;
	static BufferedInputStream bufferedFileInputStream = null;

    public static void main(String[] args) {

        String serverAddress = getAddress();
        int port = getPortNumber();
        String fileName = "";

        while(!establishConnection(port, serverAddress)){
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

            int numBytes = 0;
            byte [] fromFileBuffer = new byte[117];

            // Send the file
			for (boolean fileEnded = false; !fileEnded;) {
				numBytes = bufferedFileInputStream.read(fromFileBuffer);
				fileEnded = numBytes < 117;
                System.out.println("Bytes being written: " + numBytes);
				toServer.writeInt(1);
				toServer.writeInt(numBytes);
				toServer.write(fromFileBuffer);
				toServer.flush();
			}

            fileInputStream.close();
            bufferedFileInputStream.close();

            System.out.println("Finish sending data.");
			
        } catch (Exception exception) {
            System.out.println("Something wrong with sending the packets... Please try again!");
        }

    }

    // send filename 
    public static void sendFileName(String fileName) {
        try {
			System.out.println("Sending filename '"+ fileName + "'...");

			// Send the filename
			toServer.writeInt(0);

            System.out.println("Filename bytes: "+ fileName.getBytes().length);
			toServer.writeInt(fileName.getBytes().length);
			toServer.write(fileName.getBytes());
			toServer.flush();

			System.out.println("File name sent successfully!");
		}
		catch (Exception exception) {
			System.out.println("Cannot transfer file... Please try again.");
		}
    }

    // end connection and end program.
	public static void endConnection () {
		System.out.println("Closing connection...");
		try {
			toServer.writeInt(99);
			clientSocket.close();
			System.out.println("Connection closed.");
		} catch (Exception exception) {
			System.out.println("Connection already closed.");
		}
	}

    // establish connection
	public static boolean establishConnection(int port, String serverAddress) {
		try {
			clientSocket = new Socket(serverAddress, port);	
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());
			return true;
		} catch (Exception e) {
			System.out.println("Cannot establish connection. Please check address and port.");
			return false;
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

		while(!valid) {
			System.out.print("Please enter port number that you want to use (press enter to use default port of '44444'): ");

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
			}
			catch (Exception exception) {
				System.out.println("Invalid input! Please enter a port NUMBER between 0 to 65353...");
			}
		}

		return port;
	}

    // to get user input on what file they want to send and check whether it exists first
    public static String getFileName () {

        boolean exist = false; // check if file exist
        String fileName = ""; // stores the filename

        while (!exist) {
            System.out.print("\nPlease enter filename that you want to send (press enter to quit): ");

            fileName = scanner.nextLine();

            if (fileName == "") break;

            System.out.println("Checking if file, " + fileName + ", exists in current directory...");

            File file = new File(fileName);

            if (file.exists() && !file.isDirectory()) {
                System.out.println("Found file!");
                
                exist = true;
            }
            else {
                System.out.println("File not found. Please enter a valid file name and ensure that file is in current directory!");
            }
        }

        return fileName;
    }
}