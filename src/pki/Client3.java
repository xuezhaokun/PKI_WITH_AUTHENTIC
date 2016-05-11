package pki;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import java.util.Base64;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class Client3 {
	
	private static KeyPair readClient3KeyPair(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client3kpSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client3kpSocket.accept();
		ObjectInputStream ois3 = new ObjectInputStream(connectionSocket.getInputStream());
		KeyPairMsg kpFromCA = (KeyPairMsg)ois3.readObject();
		connectionSocket.close();
		client3kpSocket.close();
		return kpFromCA.getKeypair();
	}
	private static PublicKeysMsg getPublicKeyObj(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client3PubkMsgSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client3PubkMsgSocket.accept();
		ObjectInputStream oisca = new ObjectInputStream(connectionSocket.getInputStream());
		PublicKeysMsg publicKeysFromCA = (PublicKeysMsg)oisca.readObject();
		connectionSocket.close();
		client3PubkMsgSocket.close();
		return publicKeysFromCA;
	}
	public static PublicKey getPublicKey(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket publickKeySocket = new ServerSocket(portNumber);
		
		Socket connectionSocket = publickKeySocket.accept();
		BufferedReader inFromClient1OrRouter2 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
		String pubk = inFromClient1OrRouter2.readLine(); 
		byte[] decodedPublicKey = Base64.getDecoder().decode(pubk);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
		connectionSocket.close();
		publickKeySocket.close();
		return publicKey;
		
	}
	
	private static byte[] decrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception{
		Cipher cipher = Cipher.getInstance(xform);
	    cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	// decrypt authentic msg
	private static byte[] decryptAuthenticMsgFromRouter2(byte[] inpBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}

	private static byte[] decryptAuthenticMsgAtClient3(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		//return cipher.doFinal(inpBytes);
		StringBuffer sb = new StringBuffer();
		for (byte b : cipher.doFinal(inpBytes)) {
			sb.append(String.format("%02x", b & 0xff));
		}

		String hash = sb.substring(sb.length() - 32);
		
		return hash.getBytes("UTF-8");
	}

	private static Message readMsgFromRouter2(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client3MsgSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client3MsgSocket.accept();
		ObjectInputStream ois2 = new ObjectInputStream(connectionSocket.getInputStream());
		Message msgFromRouter2 = (Message)ois2.readObject();
		connectionSocket.close();
		client3MsgSocket.close();
		return msgFromRouter2;
	}
	private static byte[] decryptMsg(byte[] encryptedMsg, PublicKey client1_publickey, PublicKey router2_publickey) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		encryptedMsg = Client3.decrypt(encryptedMsg, router2_publickey, xform);
		//System.out.println("first decrypted msg: " + encodedByClient1);
		encryptedMsg = Client3.decrypt(encryptedMsg, client1_publickey, xform);
		//String encodedHashMsg = Hex.encodeHex(encryptedMsg);
		StringBuffer sb = new StringBuffer();
		for (byte b : encryptedMsg) {
			sb.append(String.format("%02x", b & 0xff));
		}

		String hash = sb.substring(sb.length() - 32);
		
		return hash.getBytes("UTF-8");
	}
	private static void sendMsgToApp2(KeyPair kp, PublicKey client1Pubk, PublicKey router2Pubk, Message msg, int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		PrivateKey prvk = kp.getPrivate();
		Socket client3Socket = new Socket("localhost", portNumber);
		
		byte[] decodedMsg = Base64.getDecoder().decode(msg.getEncodedMsg());
		byte[] decodedAuthenticMsg = Base64.getDecoder().decode(msg.getAuthenticMsg());
		byte[] decryptedAuthenticMsgFromRouter2 = decryptAuthenticMsgFromRouter2(decodedAuthenticMsg, router2Pubk, xform);
		byte[] decryptedAuthenticMsgAtClient3 = decryptAuthenticMsgAtClient3(decryptedAuthenticMsgFromRouter2, prvk, xform);
		String decryptedStringAuthentic = Base64.getEncoder().encodeToString(decryptedAuthenticMsgAtClient3);
		
		//byte[] encryptedMsg = encrypt(decodedMsg, prvk, xform);
		byte[] decryptedMsg = Client3.decryptMsg(decodedMsg, client1Pubk, router2Pubk);
		String decryptedStringMsg = Base64.getEncoder().encodeToString(decryptedMsg);
		
		msg.setEncodedMsg(decryptedStringMsg);
		msg.setAuthenticMsg(decryptedStringAuthentic);
		String[] updatedRoute = {"Client3"};
		msg.setRoute(updatedRoute);
		System.out.println("sending msg: " + msg.toString());
		
        ObjectOutputStream oos1 = new ObjectOutputStream(client3Socket.getOutputStream());
        oos1.writeObject(msg);
        client3Socket.close();
	}
	
	public static void main(String[] args) throws Exception {
		KeyPair client3kp = Client3.readClient3KeyPair(4446);
		PublicKeysMsg pubkeys = Client3.getPublicKeyObj(6666);
		PublicKey router2Pubk = pubkeys.getRouter2Pubk();
		PublicKey client1Pubk = pubkeys.getClient1Pubk();
		Message msgFromRouter2 = Client3.readMsgFromRouter2(3456);
		Client3.sendMsgToApp2(client3kp, client1Pubk, router2Pubk, msgFromRouter2, 4567);

	}

}
