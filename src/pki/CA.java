package pki;
import java.io.DataOutputStream;
import java.io.IOException;
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
	
	private static void sendPublickey(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		Socket caPublicKeySocket = new Socket("localhost", portNumber);
		DataOutputStream pkdos = new DataOutputStream(caPublicKeySocket.getOutputStream());
		PublicKey pubk = kp.getPublic();
		String encoded = Base64.getEncoder().encodeToString(pubk.getEncoded());
		pkdos.writeBytes(encoded + '\n');
		pkdos.close();
	}

	private static void assignKeyPair(KeyPair kp, int portNumber) throws UnknownHostException, IOException{
		Socket keyPairSocket = new Socket("localhost", portNumber);
		KeyPairMsg keyPairMsgObj = new KeyPairMsg(kp);
        System.out.println("sending msg: " + keyPairMsgObj.toString());
        ObjectOutputStream kpoos = new ObjectOutputStream(keyPairSocket.getOutputStream());
        kpoos.writeObject(keyPairMsgObj);
        keyPairSocket.close();
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnknownHostException, IOException {
		// assign key pairs
		KeyPair client1_kp = CA.generateKeyPair();
		CA.assignKeyPair(client1_kp, 4444);
		KeyPair router2_kp = CA.generateKeyPair();
		CA.assignKeyPair(router2_kp, 4445);
		KeyPair client3_kp = CA.generateKeyPair();
		CA.assignKeyPair(client3_kp, 4446);
		
		// send public keys
		// send client1 public key to app1
		CA.sendPublickey(client1_kp, 5555);
		// send router2 public key to app1
		CA.sendPublickey(router2_kp, 5556);
		// send client3 public key to app1
		CA.sendPublickey(client3_kp, 5557);
		
		// send client1 public key to router2
		CA.sendPublickey(client1_kp, 6666);
		// send router2 public key to client3
		CA.sendPublickey(router2_kp, 6667);
	}

}
