package pki;
import java.io.Serializable;
import java.util.Arrays;

public class Message implements Serializable{

	private static final long serialVersionUID = 1L;
	private String orginalMsg;
	private String encodedMsg;
	private String authenticMsg;
	private String[] route;
	
	public Message(String orginalMsg, String encodedMsg, String authenticMsg,String[] route) {
		super();
		this.orginalMsg = orginalMsg;
		this.encodedMsg = encodedMsg;
		this.authenticMsg = authenticMsg;
		this.route = route;
	}

	public String getOrginalMsg() {
		return orginalMsg;
	}

	public void setOrginalMsg(String orginalMsg) {
		this.orginalMsg = orginalMsg;
	}

	public String getEncodedMsg() {
		return encodedMsg;
	}

	public void setEncodedMsg(String encodedMsg) {
		this.encodedMsg = encodedMsg;
	}

	public String[] getRoute() {
		return route;
	}

	public void setRoute(String[] route) {
		this.route = route;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}

	public String getAuthenticMsg() {
		return authenticMsg;
	}

	public void setAuthenticMsg(String authenticMsg) {
		this.authenticMsg = authenticMsg;
	}

	@Override
	public String toString() {
		return "Message [orginalMsg=" + orginalMsg + ", encodedMsg=" + encodedMsg + ", authenticMsg=" + authenticMsg
				+ ", route=" + Arrays.toString(route) + "]";
	}
	
}
