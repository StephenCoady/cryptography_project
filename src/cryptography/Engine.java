package cryptography;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Engine {

	Client client;
	Server server;

	public Engine() throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException{
		client = new Client();
		server = new Server();
	}
	/**
	 * @param args
	 * @throws IOException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws NoSuchPaddingException 
	 * @throws ClassNotFoundException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
		Engine sslApp = new Engine();
		sslApp.run();
	}



	private void run() throws NoSuchAlgorithmException, IOException {
		int option = menu();
		while (option != 0) {
			switch (option) {
			case 1: 
				server.newKey();
				break;
			case 2: 
				client.generateSessionKey();
				break;
			case 3: 
				client.encryptSessionKey(sessionKey);
				break;
			case 4: 
				server.decryptSessionKey(encryptedSessionKey);
				break;
			case 5: 
				client.encryptMessage(sessionKey);
				break;
			case 6: 
				server.hashMessage(hash);
				break;
			default:
				break;
			}
			option = menu();
		}
		System.out.println("Exiting... bye");
	}

	private int menu() {
		System.out.println("1) Server: Generate RSA key pair and send");
		System.out.println("2) Client: Generate session key");
		System.out.println("3) Client: Encrypt session key using public key and send");
		System.out.println("4) Server: Decrypt session key");
		System.out.println("5) Client: Encrypt message using session key");
		System.out.println("6) Server: Decrypt message using session key ");
		System.out.println("7) Client: Append session key to message and hash");
		System.out.println("8) Server: Append session key to the message and compare hash outputs");
		System.out.println("0) Exit ==>>" + "\n");
		Scanner sc = new Scanner(System.in);
		int option = sc.nextInt();
		sc.close();
		return option;
	}

	private String inputMessage(){
		Scanner sc = new Scanner(System.in);
		String message = sc.next();
		return message;
	}
}
