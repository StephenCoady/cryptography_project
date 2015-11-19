package cryptography;

import java.io.*;
import java.security.*;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Server{

	private SecretKey sessionKey;
	private String message;
	private byte[] hash;
	

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

//			String keys = Base64.getEncoder().encodeToString(this.sessionKey.getEncoded());
//			System.out.println("Encoding on server side: "+keys);


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
	
	public String getMessage(){
		return this.message;
	}
	
	public void hashMessage() throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		byte [] sessionBytes = this.sessionKey.getEncoded();
		byte [] finalMessage = new byte[this.message.getBytes().length+sessionBytes.length];
		
		this.hash = md.digest(finalMessage); 
	}
	
	public byte[] getHash(){
		return this.hash;
	}
}