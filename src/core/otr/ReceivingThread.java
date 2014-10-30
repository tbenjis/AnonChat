package core.otr;

import java.io.BufferedReader;
import java.net.SocketException;

import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.StringTLV;

public class ReceivingThread extends Thread{
	private BufferedReader in;
	private OTRInterface us;
	private String accountname;
	private String protocol;
	private String sender;
	private OTRContext conn;
	private OTRCallbacks callback;
	
	public ReceivingThread(BufferedReader in, OTRInterface us, String accName,
			String prot, String sendName, OTRCallbacks callbacks){
		this.in=in;
		this.us=us;
		this.accountname = accName;
		this.protocol = prot;
		this.sender = sendName;
		this.conn=us.getContext(accName, prot, sendName);
		this.callback = callbacks;
	}
	
	public void run(){
		String res;
		while(true){
			try {
				res=in.readLine();
				System.out.println("\033[31mFrom network:"+res.length()+":\033[35m"+res+"\033[0m");
				StringTLV stlv = us.messageReceiving(accountname, protocol, sender, res, callback);
				if(stlv!=null){
					res=stlv.msg;
					System.out.println("\033[31mFrom OTR:"+res.length()+":\033[0m"+res);
				}
			} catch (SocketException e) {
				return;
			}
			catch (Exception e) {
				e.printStackTrace();
				return;
			}
		}
	}
}
