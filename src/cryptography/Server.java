package cryptography;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Server{

	private SecretKey sessionKey;
	private StringBuffer message;
	
	public Server(){
	}
	
	public static void main(String [ ] args){
		//THIS IS NEW
	}


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

		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}

	//	public void decryptMessage(){
	//		//start decrypt
	//	      byte[] iv = new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	//        IvParameterSpec ips = new IvParameterSpec(iv);
	//
	//       // Create AES cipher instance
	//        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	//        
	//        // Initialize the cipher for decryption
	//        aesCipher.init(Cipher.DECRYPT_MODE, key, ips);
	//        
	//        // Read ciphertext from file and decrypt it
	//        FileInputStream fis = new FileInputStream("scrambled");
	//        BufferedInputStream bis = new BufferedInputStream(fis);
	//        CipherInputStream cis = new CipherInputStream(bis, aesCipher);
	//        
	//        StringBuffer plaintext = new StringBuffer();
	//        int c;
	//        while ((c = cis.read()) != -1)
	//            plaintext.append((char) c);
	//        cis.close();
	//        bis.close();
	//        fis.close();
	//        
	//        System.out.println("Plaintext: " + plaintext.toString());
	//	}

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

			String keys = Base64.getEncoder().encodeToString(this.sessionKey.getEncoded());
			System.out.println("Encoding on server side: "+keys);

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
			this.message = plaintext;
			System.out.println("Plaintext: " + plaintext.toString());


		}
		catch (Exception e)
		{
			System.out.println(e);
		}

	}

	public void hashMessage(byte[] hash) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		byte [] sessionBytes = this.sessionKey.getEncoded();
		byte [] finalMessage = new byte[this.message.toString().getBytes().length+sessionBytes.length];
		
		byte outputHash[] = md.digest(finalMessage);
		
		boolean retVal = Arrays.equals(outputHash, hash);
		System.out.println(retVal);

		StringBuffer hexString = new StringBuffer();
	      for (int i=0;i<outputHash.length;i++) {
	          hexString.append(Integer.toHexString(0xF & outputHash[i]>>4));
	          hexString.append(Integer.toHexString(0xF & outputHash[i]));
	         hexString.append (" ");
	      }
	      System.out.println ("Hash value: " + hexString.toString());
	   
	}
}