

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
 * A server model. Used to generate public/private RSA key pair. 
 * Uses this private key to decrypt the session key sent to it by the client
 */
public class Server{

	private SecretKey sessionKey;
	private String message;
	private byte[] hash;
	private byte[] messageBytes;


	public void newKey(){
		try
		{
			// Generate RSA key pair
			KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

			// File for writing private key
			FileOutputStream privateKeyFOS = new FileOutputStream("private key");
			ObjectOutputStream privateKeyOOS = new ObjectOutputStream(privateKeyFOS);

			// File for writing publickey
			FileOutputStream publicKeyFOS = new FileOutputStream("public key");
			ObjectOutputStream publicKeyOOS = new ObjectOutputStream(publicKeyFOS);

			// Write the keys to respective files
			privateKeyOOS.writeObject(keyPair.getPrivate());
			publicKeyOOS.writeObject(keyPair.getPublic());

			privateKeyOOS.close();
			publicKeyOOS.close();
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}

	public SecretKey getSessionKey(){
		return this.sessionKey;
	}

	public void decryptSessionKey(byte[] encryptedSessionKey){

		try
		{
			// File containing RSA private key
			FileInputStream keyFIS = new FileInputStream("private key");
			ObjectInputStream keyOIS = new ObjectInputStream(keyFIS);

			// Create RSA cipher instance
			Cipher rsaCipher = Cipher.getInstance("RSA");

			// Initialize the cipher for decryption
			rsaCipher.init(Cipher.DECRYPT_MODE, (PrivateKey) keyOIS.readObject());

			keyOIS.close();
			keyFIS.close();


			this.sessionKey = new SecretKeySpec (rsaCipher.doFinal(encryptedSessionKey), "AES");



		}
		catch (Exception e)
		{
			System.out.println(e);
		}

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
		FileInputStream fis = new FileInputStream("scrambled");
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
		FileOutputStream fos = new FileOutputStream("scrambledFromServer");
		// Read first command-line arg into a buffer.
		// This is the messge to be encrypted
		byte plaintext[] = messageToBytes(message);

		// Encrypt the plaintext
		byte[] ciphertext = aesCipher.doFinal(plaintext);

		// Write ciphertext to file
		fos.write(ciphertext);
		fos.close();
	}

	/*
	 * convert message to bytes for ease of use
	 */
	public byte[] messageToBytes(String message){

		byte[] plaintext = message.getBytes();
		return this.messageBytes = plaintext;
	}

	public String getMessage(){
		return this.message;
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
		byte [] finalMessage = new byte[this.message.getBytes().length+sessionBytes.length];

		for (int i = 0; i < finalMessage.length; ++i)
		{
		    finalMessage[i] = i < this.message.getBytes().length ? this.message.getBytes()[i] : sessionBytes[i - this.message.getBytes().length];
		}
		
		this.hash = md.digest(finalMessage); 
	}

	public byte[] getHashValue(){
		return this.hash;
	}
}
