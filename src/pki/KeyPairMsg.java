package pki;
import java.io.Serializable;
import java.security.*;

public class KeyPairMsg implements Serializable{

	private static final long serialVersionUID = 1L;
	private KeyPair keypair;
	
	public KeyPairMsg(KeyPair keypair) {
		super();
		this.keypair = keypair;
	}

	public KeyPair getKeypair() {
		return keypair;
	}

	public void setKeypair(KeyPair keypair) {
		this.keypair = keypair;
	}

	@Override
	public String toString() {
		return "KeyPairMsg [keypair=" + keypair + "]";
	}

	
}
