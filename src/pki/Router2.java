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

public class Router2 {
	
	private static KeyPair readRouter2KeyPair(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket router2kpSocket = new ServerSocket(portNumber);
		Socket connectionSocket = router2kpSocket.accept();
		ObjectInputStream ois1 = new ObjectInputStream(connectionSocket.getInputStream());
		KeyPairMsg kpFromCA = (KeyPairMsg)ois1.readObject();
		connectionSocket.close();
		router2kpSocket.close();
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
		while(true){
			Socket connectionSocket = publickKeySocket.accept();
			BufferedReader inFromClient1OrRouter2 = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			String pubk = inFromClient1OrRouter2.readLine(); 
			byte[] decodedPublicKey = Base64.getDecoder().decode(pubk);
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
			publickKeySocket.close();
			return publicKey;
		}
	}
	
	// encrypt msg
	private static byte[] encrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	// decrypt authentic msg
	private static byte[] decryptAuthenticMsgFromClient1(byte[] inpBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}

	private static byte[] decryptAuthenticMsgAtRouter2(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	private static Message readMsgFromClient1(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket router2MsgSocket = new ServerSocket(portNumber);
		Socket connectionSocket = router2MsgSocket.accept();
		ObjectInputStream ois1 = new ObjectInputStream(connectionSocket.getInputStream());
		Message msgFromClient1 = (Message)ois1.readObject();
		connectionSocket.close();
		router2MsgSocket.close();
		return msgFromClient1;
	}
	
	private static void sendMsgToClient3(KeyPair kp, PublicKey client1Pubk, Message msg, int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		PrivateKey prvk = kp.getPrivate();
		Socket router2Socket = new Socket("localhost", portNumber);
		
		byte[] decodedMsg = Base64.getDecoder().decode(msg.getEncodedMsg());
		byte[] decodedAuthenticMsg = Base64.getDecoder().decode(msg.getAuthenticMsg());
		byte[] decryptedAuthenticMsgFromClient1 = decryptAuthenticMsgFromClient1(decodedAuthenticMsg, client1Pubk, xform);
		byte[] decryptedAuthenticMsgAtRouter2 = decryptAuthenticMsgAtRouter2(decryptedAuthenticMsgFromClient1, prvk, xform);
		byte[] encryptedAuthenticMsg = encrypt(decryptedAuthenticMsgAtRouter2, prvk, xform);
		String authenticStringMsg = Base64.getEncoder().encodeToString(encryptedAuthenticMsg);
		
		
		byte[] encryptedMsg = encrypt(decodedMsg, prvk, xform);
		String encodedMsg = Base64.getEncoder().encodeToString(encryptedMsg);
		msg.setEncodedMsg(encodedMsg);
		msg.setAuthenticMsg(authenticStringMsg);
		String[] updatedRoute = {"Client3"};
		msg.setRoute(updatedRoute);
		System.out.println("sending msg: " + msg.toString());
		
        ObjectOutputStream oos1 = new ObjectOutputStream(router2Socket.getOutputStream());
        oos1.writeObject(msg);
        router2Socket.close();
	}
	
	
	public static void main(String[] args) throws Exception {
		KeyPair router2kp = Router2.readRouter2KeyPair(4445);
		//PublicKey client1Pubk = Router2.getPublicKey(6668);
		PublicKeysMsg pubkeys = Router2.getPublicKeyObj(6667);
		//PublicKey router2Pubk = pubkeys.getRouter2Pubk();
		PublicKey client1Pubk = pubkeys.getClient1Pubk();
		Message msgFromClient1 = Router2.readMsgFromClient1(2345);
		Router2.sendMsgToClient3(router2kp, client1Pubk, msgFromClient1, 3456);
	}

}
