package pki;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import java.util.Base64;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
public class Client1 {
	
	private static KeyPair readClient1KeyPair(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client1kpSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client1kpSocket.accept();
		ObjectInputStream ois1 = new ObjectInputStream(connectionSocket.getInputStream());
		KeyPairMsg kpFromCA = (KeyPairMsg)ois1.readObject();
		connectionSocket.close();
		return kpFromCA.getKeypair();
	}
	
	// encrypt msg
	private static byte[] encrypt(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	// decrypt authentic msg
	private static byte[] decryptAuthenticMsg(byte[] inpBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	private static Message readMsgFromApp1(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client1MsgSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client1MsgSocket.accept();
		ObjectInputStream ois1 = new ObjectInputStream(connectionSocket.getInputStream());
		Message msgFromApp1 = (Message)ois1.readObject();
		connectionSocket.close();
		return msgFromApp1;
	}
	
	private static void sendMsgToRouter2(KeyPair kp, Message msgFromApp1, int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		String msg = msgFromApp1.getOrginalMsg();
		
		String authenticMsg = msgFromApp1.getAuthenticMsg();
		byte[] decodedAuthenticMsg = Base64.getDecoder().decode(authenticMsg);
		PrivateKey prvk = kp.getPrivate();
		byte[] decryptedAuthenticMsg =  decryptAuthenticMsg(decodedAuthenticMsg, prvk, xform);
		byte[] encryptedAuthenticMsg = encrypt(decryptedAuthenticMsg, prvk, xform);
		String authenticStringMsg = Base64.getEncoder().encodeToString(encryptedAuthenticMsg);
		
		String original = msg;
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(original.getBytes());
		byte[] digest = md.digest();
		
		Socket client1Socket = new Socket("localhost", portNumber);
		byte[] encryptedMsg = encrypt(digest, prvk, xform);
		String encodedMsg = Base64.getEncoder().encodeToString(encryptedMsg);
		
		String[] updatedRoute = {"Router2", "Client3"};
		
        Message msgObj = new Message(original, encodedMsg, authenticStringMsg, updatedRoute);
        System.out.println("sending msg: " + msgObj.toString());
        ObjectOutputStream oos1 = new ObjectOutputStream(client1Socket.getOutputStream());
        oos1.writeObject(msgObj);
        
		//outToRouter2.writeBytes(encodedMsg + '\n');
        client1Socket.close();
	}
	
	public static void main(String[] args) throws Exception {
		KeyPair client1Kp = Client1.readClient1KeyPair(4444);
		Message msgFromApp1 = Client1.readMsgFromApp1(1234);
		Client1.sendMsgToRouter2(client1Kp, msgFromApp1, 2345);
	}

}
