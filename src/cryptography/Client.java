package cryptography;
import java.io.*;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Client{

	private byte[] messageBytes;
	private SecretKey sessionKey;
	private byte[] encryptedSessionKey;
	private byte[] hash;



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

	public byte[] messageToBytes(String message){

		byte[] plaintext = message.getBytes();
		return this.messageBytes = plaintext;
	}

	public void hashMessage() throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		byte [] sessionBytes = this.sessionKey.getEncoded();
		byte [] finalMessage = new byte[this.messageBytes.length+sessionBytes.length];
		
		this.hash = md.digest(finalMessage); 
	}
	
	public byte[] getHashValue(){
		return this.hash;
	}
}