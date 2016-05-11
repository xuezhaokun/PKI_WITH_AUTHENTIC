package pki;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.io.ObjectOutputStream;
public class CA {
	
	public static KeyPair generateKeyPair () throws NoSuchAlgorithmException {
		// Generate a key-pair
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(512); // 512 is the keysize.
		KeyPair kp = kpg.generateKeyPair();
		return kp;
	}
	
	// send public keys
	private static void sendObjPublickey(PublicKeysMsg pubkMsg, int portNumber) throws Exception {
		Socket pkSocket = new Socket("localhost", portNumber);
        ObjectOutputStream oos1 = new ObjectOutputStream(pkSocket.getOutputStream());
        oos1.writeObject(pubkMsg);
        pkSocket.close();
	}
	
	private static void sendPublickey(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		
		Socket caSocket = new Socket("localhost", portNumber);
		DataOutputStream outToClient3 = new DataOutputStream(caSocket.getOutputStream());
		PublicKey pubk = kp.getPublic();
		String encoded = Base64.getEncoder().encodeToString(pubk.getEncoded());
		outToClient3.writeBytes(encoded + '\n');
		outToClient3.close();
		caSocket.close();
	}

	private static void assignKeyPair(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		Socket keyPairSocket = new Socket("localhost", portNumber);
		KeyPairMsg keyPairMsgObj = new KeyPairMsg(kp);
        System.out.println("sending msg: " + keyPairMsgObj.toString());
        ObjectOutputStream kpoos = new ObjectOutputStream(keyPairSocket.getOutputStream());
        kpoos.writeObject(keyPairMsgObj);
        keyPairSocket.close();
	}
	
	public static void main(String[] args) throws Exception {
		// assign key pairs
		KeyPair client3_kp = CA.generateKeyPair();
		CA.assignKeyPair(client3_kp, 4446);
		KeyPair router2_kp = CA.generateKeyPair();
		CA.assignKeyPair(router2_kp, 4445);
		KeyPair client1_kp = CA.generateKeyPair();
		CA.assignKeyPair(client1_kp, 4444);
		
		PublicKeysMsg pubksToClient3 = new PublicKeysMsg(client1_kp.getPublic(), router2_kp.getPublic(), null); 
		PublicKeysMsg pubksToRouter2 = new PublicKeysMsg(client1_kp.getPublic(), null, null); 
		PublicKeysMsg pubksToApp1 = new PublicKeysMsg(client1_kp.getPublic(), router2_kp.getPublic(), client3_kp.getPublic()); 
		CA.sendObjPublickey(pubksToClient3, 6666);
		CA.sendObjPublickey(pubksToRouter2, 6667);
		CA.sendObjPublickey(pubksToApp1, 6668);
		// send router2 public key to client3
		//CA.sendPublickey(router2_kp, 6543);
		//CA.sendPublickey(client1_kp, 6542);
		// send client1 public key to router2
		//CA.sendPublickey(client1_kp, 6668);
		

		// send public keys
		// send client1 public key to app1
		//CA.sendPublickey(client1_kp, 5555);
		// send router2 public key to app1
		//CA.sendPublickey(router2_kp, 5556);
		// send client3 public key to app1
		//CA.sendPublickey(client3_kp, 5557);
	}

}
