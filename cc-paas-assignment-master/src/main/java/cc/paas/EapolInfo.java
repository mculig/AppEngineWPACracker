package cc.paas;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class EapolInfo {

	//Source and destination MAC addresses
	byte[] STA;
	byte[] BSSID;
	//Source and destination nonces
	byte[] ANonce;
	byte[] SNonce;
	//EAPOL MIC
	byte[] MIC;
	//Version dictates if HmacMD5 or HmacSHA1 is used
	Integer Version;
	//SSID is the name of the AP
	String SSID;
	//The appropriate contents of the last frame used to calculate the MIC
	byte[] secondFrame;
	
	
	public EapolInfo(String STA, String BSSID, String ANonce, String SNonce, String MIC, Integer Version, String SSID, String secondFrame) throws DecoderException
	{
		this.STA=Hex.decodeHex(STA);
		this.BSSID=Hex.decodeHex(BSSID);
		this.ANonce=Hex.decodeHex(ANonce);
		this.SNonce=Hex.decodeHex(SNonce);
		this.MIC=Hex.decodeHex(MIC);
		this.Version=Version;
		this.SSID=SSID;
		//The second frame is accepted as HEX, decoded to a byte and then the Key MIC bytes are set to 0 
		this.secondFrame=Hex.decodeHex(secondFrame);
		//The key MIC needs to be set to 0
		for(int i=81;i<97;i++)
		{
			this.secondFrame[i]=(byte)0;
		}
	}
	
	public EapolInfo(byte[] STA, byte[] BSSID, byte [] ANonce, byte[] SNonce, byte[] MIC, Integer Version, String SSID, byte[] secondFrame) throws DecoderException
	{
		this.STA=STA;
		this.BSSID=BSSID;
		this.ANonce=ANonce;
		this.SNonce=SNonce;
		this.MIC=MIC;
		this.Version=Version;
		this.SSID=SSID;
		this.secondFrame=secondFrame;
		//The key MIC needs to be set to 0
		for(int i=81;i<97;i++)
		{
			this.secondFrame[i]=(byte)0;
		}
	}
	
}
