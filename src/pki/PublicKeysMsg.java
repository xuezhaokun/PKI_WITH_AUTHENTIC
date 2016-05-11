package pki;
import java.io.Serializable;
import java.security.*;

public class PublicKeysMsg implements Serializable{

	
	/**
	 * 
	 */
	private static final long serialVersionUID = -7955979333020359580L;

	private PublicKey client1Pubk;
	private PublicKey router2Pubk;
	private PublicKey client3Pubk;
	
	public PublicKeysMsg(PublicKey client1Pubk, PublicKey router2Pubk, PublicKey client3Pubk) {
		super();
		this.client1Pubk = client1Pubk;
		this.router2Pubk = router2Pubk;
		this.client3Pubk = client3Pubk;
	}

	public PublicKey getClient1Pubk() {
		return client1Pubk;
	}

	public void setClient1Pubk(PublicKey client1Pubk) {
		this.client1Pubk = client1Pubk;
	}

	public PublicKey getRouter2Pubk() {
		return router2Pubk;
	}

	public void setRouter2Pubk(PublicKey router2Pubk) {
		this.router2Pubk = router2Pubk;
	}

	public PublicKey getClient3Pubk() {
		return client3Pubk;
	}

	public void setClient3Pubk(PublicKey client3Pubk) {
		this.client3Pubk = client3Pubk;
	}

	@Override
	public String toString() {
		return "PublicKeysMsg [client1Pubk=" + client1Pubk + ", router2Pubk=" + router2Pubk + ", client3Pubk="
				+ client3Pubk + "]";
	}
	
	
}