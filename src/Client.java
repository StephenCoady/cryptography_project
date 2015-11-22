
import java.io.*;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * By Stephen Coady (20064122) & Colum Foskin (20062042)
 * 
 * Assignment - Client-Server security handshake
 * Lecturer - Jimmy McGibney
 * Module - Applied Cryptography
 *
 *
 * A client model. Used to generate a session key.
 * Can encrypt and decrypt messages
 */

public class Client{

	private byte[] messageBytes;
	private SecretKey sessionKey;
	private byte[] encryptedSessionKey;
	private byte[] hash;
	private String message;



	public void generateSessionKey() throws NoSuchAlgorithmException, IOException{
		int numBytes = 16;

		SecureRandom sRandom = SecureRandom.getInstance("SHA1PRNG");

		byte [] sessionKeyBytes = new byte[numBytes];
		sRandom.nextBytes(sessionKeyBytes);

		SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");
		//		String key = Base64.getEncoder().encodeToString(sessionKey.getEncoded());
		//		System.out.println("Encoding from client side: "+key);
		this.sessionKey = sessionKey;
	}

	public SecretKey getSessionKey(){
		return sessionKey;
	}

	public void encryptSessionKey(SecretKey sessionKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, ClassNotFoundException, IOException, NoSuchAlgorithmException, NoSuchPaddingException{

		FileInputStream keyFIS = new FileInputStream("public key");
		ObjectInputStream keyOIS = new ObjectInputStream(keyFIS);

		Cipher cipher = Cipher.getInstance("RSA");

		// Initialize the cipher for encryption
		cipher.init(Cipher.ENCRYPT_MODE, (PublicKey) keyOIS.readObject());

		keyOIS.close();
		keyFIS.close();

		byte[] ciphertext = cipher.doFinal(sessionKey.getEncoded());


		this.encryptedSessionKey = ciphertext;
	}

	public byte[] getEncryptedSessionKey(){
		return this.encryptedSessionKey;
	}

	public void encryptMessage(SecretKey sessionKey, String message) throws IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException{

		// set IV (required for CBC)
		byte[] iv ={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				0x00,0x00,0x00,0x00,0x00};
		IvParameterSpec ips = new IvParameterSpec(iv);
		// Create AES cipher instance
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		// Initialize the cipher for encryption
		aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ips);

		// File for writing output
		FileOutputStream fos = new FileOutputStream("scrambled");
		// Read first command-line arg into a buffer.
		// This is the messge to be encrypted
		byte plaintext[] = messageToBytes(message);

		// Encrypt the plaintext
		byte[] ciphertext = aesCipher.doFinal(plaintext);

		// Write ciphertext to file
		fos.write(ciphertext);
		fos.close();
	}
	
	public void decryptMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException{
		//start decrypt
		byte[] iv = new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
		IvParameterSpec ips = new IvParameterSpec(iv);

		// Create AES cipher instance
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// Initialize the cipher for decryption
		aesCipher.init(Cipher.DECRYPT_MODE, this.sessionKey, ips);

		// Read ciphertext from file and decrypt it
		FileInputStream fis = new FileInputStream("scrambledFromServer");
		BufferedInputStream bis = new BufferedInputStream(fis);
		CipherInputStream cis = new CipherInputStream(bis, aesCipher);

		StringBuffer plaintext = new StringBuffer();
		int c;
		while ((c = cis.read()) != -1)
			plaintext.append((char) c);
		cis.close();
		bis.close();
		fis.close();
		this.message = plaintext.toString();
	}
	
	public String getMessage(){
		return this.message;
	}

	/*
	 * convert message to bytes for ease of use
	 */
	public byte[] messageToBytes(String message){

		byte[] plaintext = message.getBytes();
		return this.messageBytes = plaintext;
	}

	/*
	 * hash the message so that the server can compare to the client's hash.
	 * this method takes the bytes of the message and combines it with the bytes of the AES key
	 * which is then hashed. this hashed is compared (by the engine) to verify they match. thus 
	 * that the client are who they say they are
	 */
	
	public void hashMessage() throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");

		byte [] sessionBytes = this.sessionKey.getEncoded();
		byte [] finalMessage = new byte[this.messageBytes.length+sessionBytes.length];

		for (int i = 0; i < finalMessage.length; ++i)
		{
		    finalMessage[i] = i < messageBytes.length ? messageBytes[i] : sessionBytes[i - messageBytes.length];
		}
		
		this.hash = md.digest(finalMessage);  
	}
	
	public byte[] getHashValue(){
		return this.hash;
	}
}
