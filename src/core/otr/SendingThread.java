package core.otr;

import java.io.BufferedReader;

import ca.uwaterloo.crysp.otr.TLV;
import ca.uwaterloo.crysp.otr.iface.OTRCallbacks;
import ca.uwaterloo.crysp.otr.iface.OTRContext;
import ca.uwaterloo.crysp.otr.iface.OTRInterface;
import ca.uwaterloo.crysp.otr.iface.OTRTLV;
import ca.uwaterloo.crysp.otr.iface.Policy;

public class SendingThread extends Thread{
	private BufferedReader in;
	private OTRContext conn;
	private OTRCallbacks callback;
	private OTRInterface us;
	private String accountname;
	private String protocol;
	private String recipient;
	
	public SendingThread(BufferedReader in, OTRInterface us, String accName,
			String prot, String recName, OTRCallbacks callbacks){
		this.in=in;
		this.us=us;
		this.accountname = accName;
		this.protocol = prot;
		this.recipient = recName;
		this.conn=us.getContext(accName, prot, recName);
		this.callback = callbacks;
	}
	
	public void run(){
		String str;
		while(true){
			try {
				str = in.readLine();
				if(str.startsWith("/isq")){
					System.out.println("Please input the question");
					String question = in.readLine();
					System.out.println("Please input the secret");
					str = in.readLine();
					conn.initiateSmp_q(question, str, callback);
				}else if(str.startsWith("/is")){
					System.out.println("Please input the secret");
					str = in.readLine();
					conn.initiateSmp(str, callback);
				}else if(str.startsWith("/rs")){
					System.out.println("Please input the secret");
					str = in.readLine();
					conn.respondSmp(str, callback);
				}else if(str.startsWith("/as")){
					conn.abortSmp(callback);
				}else if(str.startsWith("/disc")){
					conn.disconnect(callback);
				}
				else{
					System.out.println("\033[31mTo OTR:"+str.length()+":\033[0m"+str);
					OTRTLV[] tlvs = new OTRTLV[1];
					tlvs[0]=new TLV(9, "TestTLV".getBytes());
					us.messageSending(accountname, protocol, recipient,
							str, tlvs, Policy.FRAGMENT_SEND_ALL, callback);
					/*if(str.length()!=0){
						System.out.println("\033[31mTo network:"+str.length()+":\033[35m"+str+"\033[0m");
						conn.fragmentAndSend(str,  callback);
					}*/
				}
			} catch (Exception e) {
				e.printStackTrace();
				return;
			}
		}
	}
}
