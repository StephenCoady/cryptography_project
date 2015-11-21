
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/* By Stephen Coady (20064122) & Colum Foskin (20062042)
 * 
 * Assignment - Client-Server security handshake
 * Lecturer - Jimmy McGibney
 * Module - Applied Cryptography
 *
 *
 * A program to model the SSL handshake between a client and a server, using the Java Cryptography APIs.
 */

public class Engine {

	private Client client;
	private Server server;
	private String message;

	public Engine() throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException{
		client = new Client();
		server = new Server();
	}
	/**
	 * Main method
	 */
	public static void main(String[] args)  {
		try {
			Engine sslApp = new Engine();
			sslApp.run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * The method which runs the conversation between client and server.
	 * Uses switch cases to show different options to the user.
	 * 
	 */
	private void run() {
		int option = mainMenu();
		while (option != 0) {
			switch (option) {

			/*
			 * manage the client interface with options such as
			 * Initiate conversation
			 * Send message to server
			 * Read Message from server
			 */
			case 1:
				int clientOption = clientMenu();
				while (clientOption != 0){
					switch(clientOption){
					//start the conversation by generating public & private keys and also the session key
					case 1:
						try{
							server.newKey();
							System.out.println("Requesting Public RSA key from server...\n");
							Thread.sleep(3000);

							client.generateSessionKey();
							System.out.println("Generating session key...\n");
							Thread.sleep(3000);

							client.encryptSessionKey(client.getSessionKey());
							server.decryptSessionKey(client.getEncryptedSessionKey());
							System.out.println("Sending encrypted session key to server...\n");

							Thread.sleep(3000);
							System.out.println("Coversation started!");
						}catch (Exception e){
							System.out.println("Couldn't establish a connection. Please try again.");
						}
						break;
					//send a message from client side
					case 2:
						try{
							this.message = inputMessage();
							client.encryptMessage(client.getSessionKey(),this.message );
							System.out.println("Encrypting ...\n");
							Thread.sleep(3000);
							System.out.println("Sent!\n");
						}catch (Exception e){
							System.out.println("Something broke. Please try again. Did you initiate a conversation?");
						}
						break;
					//decrypt message on client side
					case 3:
						try{
							client.decryptMessage();
							System.out.println("Decrypting message from server...\n");
							Thread.sleep(3000);
							System.out.println("Decrypted message is: " + client.getMessage());
						}catch (Exception e){
							System.out.println("Oops, something went wrong. Are you sure the server sent a message? Maybe try send one from the server!");
						}
						break;
					default:
						System.out.println("Please choose a valid option.");
						break;
					}
					clientOption = clientMenu();
				}
				break;
			
			/*
			 * manage the server interface with options such as
			 * View message from client
			 * send message to client
			 * Request verification from client
			 */
			case 2:
				int serverOption = serverMenu();
				while (serverOption !=0){
					switch (serverOption){
					
					//decrypt message on server side
					case 1:
						try{
							server.decryptMessage();
							System.out.println("Decrypting message from client...\n");
							Thread.sleep(3000);
							System.out.println("Decrypted message is: " + server.getMessage());
						}catch (Exception e){
							System.out.println("Oops, something went wrong. Are you sure the client sent a message? Maybe try send one from the client!");
						}
						break;
					//send message from sever side
					case 2:
						try{
							this.message = inputMessage();
							server.encryptMessage(server.getSessionKey(),this.message );
							System.out.println("Encrypting ...\n");
							Thread.sleep(3000);
							System.out.println("Sent!");
						}catch (Exception e){
							System.out.println("Something broke. Please try again. Are you connected to a client?");
						}
						break;
					//hash the messages + AES key and ensure they are the same
					case 3:
						try{
							client.hashMessage();
							server.hashMessage();
							if(Arrays.equals(server.getHashValue(), client.getHashValue())){
								System.out.println("Hash values match! Client is authenticated.");
							}
						}catch (Exception e){
							System.out.println("Oops, something went wrong. Are you sure the client sent a message? Maybe try to send one from the client first.");
						}
					default:
						System.out.println("Please choose a valid option.");
						break;
					}
					serverOption = serverMenu();
				}
			default:
				System.out.println("Please choose a valid option.");
				break;
			}
			option = mainMenu();
		}
		System.out.println("Exiting... bye");
	}

	/**
	 * Prints a simple menu
	 * @return the user's option
	 */
	private int mainMenu() {
		System.out.println();
		System.out.println("1) Control Client");
		System.out.println("2) Control Server");
		System.out.println("0) Exit ==>>" + "\n");
		Scanner sc = new Scanner(System.in);
		int option = sc.nextInt();
		return option;
	}

	/**
	 * Prints a simple menu
	 * @return the user's option
	 */
	private int serverMenu() {
		System.out.println();
		System.out.println("1) View message from Client");
		System.out.println("2) Send encrypted message to Client");
		System.out.println("3) Request verification of identity from Client (hashing)");
		System.out.println("0) Exit ==>>" + "\n");
		Scanner sc = new Scanner(System.in);
		int option = sc.nextInt();
		return option;
	}

	/**
	 * Prints a simple menu
	 * @return the user's option
	 */
	private int clientMenu() {
		System.out.println();
		System.out.println("1) Initiate conversation with Server");
		System.out.println("2) Send encrypted message to Server");
		System.out.println("3) Read message from Server");
		System.out.println("0) Exit ==>>" + "\n");
		Scanner sc = new Scanner(System.in);
		int option = sc.nextInt();
		return option;
	}

	/**
	 * Gives the user an option to enter a message to be sent. 
	 * @return the user's message
	 */
	private String inputMessage(){
		System.out.println("Enter message to encrypt: ");
		Scanner sc = new Scanner(System.in);
		String message = sc.nextLine();
		return message;
	}
}
