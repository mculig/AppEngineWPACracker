package cc.paas;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;


public class BruteForce {
	
	EapolInfo info=null;
	List<String> dictionary=null;
	Integer dictionarySize=null;

	public BruteForce(EapolInfo info)
	{
		this.info=info;
	}
	
	public BruteForce(EapolInfo info, List<String> dictionary)
	{
		this.info=info;
		this.SetDictionary(dictionary);
	}
	
	public void SetDictionary(List<String> dictionary)
	{
		this.dictionary=dictionary;
		dictionarySize=dictionary.size();
	}
	
	public Result runAttack() throws IllegalStateException
	{
		//For storing the Pairwise Master Key
		byte[] pmk;
		//Check that a non-null EapolInfo object containing relevant information and a dictionary were set
		if(info==null)
			throw new IllegalStateException("Cannot run dictionary attack without info from handshake!");
		else if(dictionary==null)
			throw new IllegalStateException("Cannot run dictionary attack without a dictionary!");
		
		//Select the appropriate algorithm for MIC. Default "" will result in an exception and end execution. Fine by me
		//WPA-TKIP (WPA1) uses HMAC_MD5 for the EAPOL MIC
		//WPA-CCMP (WPA2) uses HMAC_SHA_1 for the EAPOL MIC
		String algorithm="";
		if(info.Version==1)
			algorithm="HMAC_MD5";
		else if(info.Version==2)
			algorithm="HMAC_SHA_1";
		
		//We only need to calculate the concatenated input A||Y||B||X for the HMAC_SHA_1 used in the PRF_X once so we do it here
		
		byte[] AYBX=null;
		
		try {
			AYBX = concatPRFInput(info.STA, info.BSSID, info.ANonce, info.SNonce);
		} catch (IOException e1) {
			e1.printStackTrace();
			return null;
		}
		
		//We need the SSID in the form of a byte array for the PBKDF2_SHA1 function that calculates the Pairwise Master Key
		byte[] SSID=info.SSID.getBytes(StandardCharsets.US_ASCII);
		
		//Other than the EAPOL MIC the rest of the calculations are completely identical for the two
		for(int i=0;i<dictionarySize;i++)
		{
			//WPA passwords are 8-63 characters of length
			if(dictionary.get(i).length()<8 || dictionary.get(i).length()>63)
				continue;
			//Step 1 - Generate Pairwise Master Key PMK
			pmk = PBKDF2_SHA1(dictionary.get(i), SSID);
			
			//Step 2 - Generate Pairwise Transient Key (PTK)
			//PTK is different for each version, but we'll just make a 512 bit one for both and that's fine. 
			try {
				byte[] ptk=PRF_X(pmk,AYBX, 512);
				//Get the Key Confirmation Key from the 1st 128 bits of the Pairwise Trainsient Key
				//Arrays.copyOfRange apparently isn't inclusive on the end so 0,16 is the 1st 16 bytes. 
				byte[] kck = Arrays.copyOfRange(ptk, 0, 16);
				//The EAPOL-key MIC is a MIC of the EAPOL-Key frames, from and including the
				//Key Descriptor Version field (of the Key Information field)
				//To and including the Key Data field, calculated with the Key MIC field set to 0
				byte[] mic = Arrays.copyOfRange(new HmacUtils(HmacAlgorithms.valueOf(algorithm), kck).hmac(info.secondFrame), 0, 16);
				if(Arrays.equals(mic, info.MIC))
				{
					return new Result(0, dictionary.size(), 1, dictionary.get(i));
				}
					
				
			} catch (IOException|IllegalArgumentException e) {
				e.printStackTrace();
				return null;
			}
			
			
		}
		return new Result(0, dictionary.size(), 0, null);
	}
	
	private static byte[] concatPRFInput(byte[] SPA, byte[] AA, byte[] ANonce, byte[] SNonce) throws IOException
	{
		//SPA Supplicant MAC -> STA MAC
		//AA Authenticator MAC -> AP's BSSID
		byte[] concatenated;
		//Min(AA,SPA)||Max(AA,SPA)||Min(ANonce,SNonce)||MAx(ANonce,SNonce)
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		//Min(AA,SPA) || Max(AA,SPA)
		if(compareArrays(AA, SPA, AA.length)<0) 
		{
			outputStream.write(AA);
			outputStream.write(SPA);
		}
		else
		{
			outputStream.write(SPA);
			outputStream.write(AA);
		}
		//Min(ANonce, SNonce) || Max(ANonce, SNonce)
		//This part is problematic as the > is reverse of what it probably should be. This indicates there may be some
		//logical error involved. Further testing will tell
		if(compareArrays(ANonce, SNonce, 32)>0)
		{
			outputStream.write(ANonce);
			outputStream.write(SNonce);
		}
		else
		{
			outputStream.write(SNonce);
			outputStream.write(ANonce);
		}
		//Result: Min(AA,SPA)||Max(AA,SPA)||Min(ANonce,SNonce)||MAx(ANonce,SNonce)
		concatenated=outputStream.toByteArray();
		//HMAC_SHA1 stuff
		//H-SHA-1(K,A,B,X)<-HMAC-SHA-1(K, A||Y||B||X) 
		//K is the pmk which should already be a properly formatted byte array and will be given as input to the PRF_X function
		//Reset the output stream for its next use
		outputStream.reset();
		//A||Y||B||X
		//A is the String "Pairwise key expansion"
		outputStream.write(new String("Pairwise key expansion").getBytes(StandardCharsets.US_ASCII));
		//Y is a single octet containing 0
		outputStream.write((byte)0);
		//B is the result of concatenating all the stuff above
		outputStream.write(concatenated);
		//X is in this case the i in the for loop in the PRF_X function (single octet)
		outputStream.write((byte)0);
		byte[] result=outputStream.toByteArray();	
		return result;
	}
	
	private static byte[] PRF_X(byte[] pmk, byte[] AYBX, Integer length) throws IOException
	{		
		byte[] result;
		ByteArrayOutputStream resultStream=new ByteArrayOutputStream();
		HmacUtils sha1=new HmacUtils(HmacAlgorithms.HMAC_SHA_1, pmk);
		int len=length/160;
		for(int i=0;i<=len;i++)
		{
			//X is i turned into a single byte. Loss of precision isn't important here since we're inside the range of a byte
			//Write the value of i to the last byte which is at length-1
			AYBX[AYBX.length-1]=(byte) i;
			//Calculate the HMAC-SHA-1 of the concatenated string A||Y||B||X and merge it all together
			resultStream.write(sha1.hmac(AYBX));
			//There is no way in hell this algorithm will be fast o.o
		}
		//Pairwise Transient Key (PTK)
		result=Arrays.copyOfRange(resultStream.toByteArray(), 0, length/8);
		return result;
	}
	
	static int compareArrays(byte[] a, byte[] b, int size)
	{
		for(int i=0;i<size;i++)
		{
			int tmp=Byte.compare(a[i], b[i]);
			if(tmp!=0)
				return tmp;
		}
		return 0;
	}
	
	private static byte[] PBKDF2_SHA1(String password, byte[] saltBytes)
	{
		//Turn the password and salt into chars and bytes
		char[] passwordChars=password.toCharArray();
		//Run the algorithm
		try {
			SecretKeyFactory skf=SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			PBEKeySpec spec = new PBEKeySpec(passwordChars, saltBytes, 4096, 256);
			SecretKey key = skf.generateSecret(spec);
			byte[] res = key.getEncoded();
			return res;
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			return null;
		}
		
	}
	
}
