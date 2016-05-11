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
import java.io.ObjectOutputStream;

public class App1 {

	
	// read public keys
	public static PublicKey getPublicKey(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		ServerSocket publickKeySocket = new ServerSocket(portNumber);
		while(true){
			Socket connectionSocket = publickKeySocket.accept();
			BufferedReader inFromCA = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream())); 
			String pubk = inFromCA.readLine(); 
			byte[] decodedPublicKey = Base64.getDecoder().decode(pubk);
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decodedPublicKey));
			return publicKey;
		}
	}
	
		
	// encrypt message with public key
	private static byte[] authenticEncrypt(byte[] inpBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inpBytes);
	}
	
	// send message to client1
	private static void sendMsgToClient1(PublicKey client1pubk, PublicKey router2pubk, PublicKey client3pubk, int portNumber) throws Exception {
		String xform = "RSA/ECB/NoPadding";
		String msg;
		BufferedReader inFromClient = new BufferedReader( new InputStreamReader(System.in)); 
		msg = inFromClient.readLine();
		
		String original = msg;
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(original.getBytes());
		byte[] digest = md.digest();
		
		Socket app1Socket = new Socket("localhost", portNumber);
		//DataOutputStream outToRouter2 = new DataOutputStream(client1Socket.getOutputStream());
		
		byte[] authenticMsg = authenticEncrypt(authenticEncrypt(authenticEncrypt(digest, client3pubk, xform), router2pubk, xform), client1pubk, xform);
		String authenticStringMsg = Base64.getEncoder().encodeToString(authenticMsg);
		
		String[] updatedRoute = {"Client1", "Router2", "Client3"};
		
        Message msgObj = new Message(original, "", authenticStringMsg, updatedRoute);
        System.out.println("sending msg: " + msgObj.toString());
        ObjectOutputStream oos1 = new ObjectOutputStream(app1Socket.getOutputStream());
        oos1.writeObject(msgObj);
        
        app1Socket.close();
	}
	
	public static void main(String[] args) throws Exception {
		
		PublicKey client1pubk = App1.getPublicKey(5555);
		PublicKey router2pubk = App1.getPublicKey(5556);
		PublicKey client3pubk = App1.getPublicKey(5557);
	
		int msgToClient1Port = 1234;
		App1.sendMsgToClient1(client1pubk, router2pubk, client3pubk, msgToClient1Port);
	}

}
