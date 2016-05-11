package pki;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

public class App2 {
	
	private static Message readMsgFromClient3(int portNumber) throws UnknownHostException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException{
		ServerSocket client3MsgSocket = new ServerSocket(portNumber);
		Socket connectionSocket = client3MsgSocket.accept();
		ObjectInputStream ois3 = new ObjectInputStream(connectionSocket.getInputStream());
		Message msgFromClient3 = (Message)ois3.readObject();
		connectionSocket.close();
		return msgFromClient3;
	}
	
	public static void main(String[] args) throws UnknownHostException, InvalidKeySpecException, NoSuchAlgorithmException, ClassNotFoundException, IOException {
		Message finalMsg = App2.readMsgFromClient3(4567);
		String original = finalMsg.getOrginalMsg();
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(original.getBytes());
		byte[] digest = md.digest();
		StringBuffer sb = new StringBuffer();
		for (byte b : digest) {
			sb.append(String.format("%02x", b & 0xff));
		}
		System.out.println(finalMsg.toString());
		System.out.println("Checking route...");
		byte[] decodedAuthenticMsg = Base64.getDecoder().decode(finalMsg.getAuthenticMsg());
		byte[] decondedMsg= Base64.getDecoder().decode(finalMsg.getEncodedMsg());
		if (Arrays.equals(sb.toString().getBytes("UTF-8"), decodedAuthenticMsg)) {
			System.out.println("Route check passed; checking message...");
			if (Arrays.equals(sb.toString().getBytes("UTF-8"), decondedMsg)) {
				System.out.println("Message check passed");
			} else {
				System.out.println("Message check failed");
			}
		} else {
			System.out.println("Route check failed.");
		}
	}

}
