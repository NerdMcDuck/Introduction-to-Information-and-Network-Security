import java.io.*;
import java.nio.charset.*;
import java.security.NoSuchProviderException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class AES_128_Decryption {
	
	
	/*Displays a list of choices
	 * Each choice is a different decryption
	 * Keeps asking for an input until the user quits. 
	 * */
	public static void main(String[] args) throws IOException, Exception, NoSuchProviderException, NoSuchPaddingException {
		
		Scanner in = new Scanner(System.in);
		System.out.println("\n1. Cipherfile 1 \n" + "2. Cipherfile 2 \n" + "3. Cipherfile 3 \n" + "4. Cipherfile 4 \n" + "5. Test File\n" + "0. Exit" );
		
		String IV; //Just the Key
		String Cipherfile;
		do{
			System.out.print("\nChoose an option by typing in the number: ");
			int choice = in.nextInt();
			
			switch(choice){
			case 0: 
				in.close();
				System.out.println("Now Exiting...");
				System.exit(0);
				
			case 1: //needs to find last  2 bytes or 16 bits
				IV = "639404CBD1A1BD2322B206C39140";
				Cipherfile = "5A052F928464CC3E437187ADCFC7E8F1CF9DEAC7059B5264E4E940D8C35AA60E2277D4832843043F593F40E4084609C886681BCF5B570D353BFF24C0E1F4A65E";
				cipher(Cipherfile, IV);	
				break;
			case 2: //needs to find last 3 bytes or 24 bits
				IV = "F806274AC0B446C18725ABDCE5";
				Cipherfile = "9D736AD64EFE153E6BEDE689772976ED83FB89D0503B27E7B4E2C4CDBE7B3BD9C1CE5E800D3929E543C3AD1B0D862990D7BCF77B74A126E27F5901EEFC5044BA";
				cipher(Cipherfile, IV);	
				break;
			case 3: //needs to find last 4 bytes or 32 bits 
				IV = "0AA4A910D451E069611D5571";
				Cipherfile = "574DD238070EC66A027F120B3D67A4B1FF20D1AAD52893CD2970E76BE73A2C4AE8AE87D1DC4CD4E6CE3733A27D401339E1E2A3FA9A0E86829284CACD5A850BCD";
				cipher(Cipherfile, IV);	
				break;
			case 4: //needs to find last 5 bytes, or 40 bits
				IV = "9D0B180B5CD9DC074ACB0E";
				Cipherfile = "7102108459F8B9726887034491C1B409C29BF90CD1895B80815ABF2434DD57327CDFF16B9CF0C90C5F39CC92FC6EF99CDDE1D0FA90236F9474DF142B6BF1B64B";
				cipher(Cipherfile, IV);
				break;
			case 5: //Test files
				long StartTime = System.currentTimeMillis();
				IV = "6F1C5CD9270AC8DDEAE6430F3096C806";
			    byte[] ciphertext =Hex.decode("1137590E7602256E37FCD36855CC9353C1F2C21171F2EC0391BEEE9A0A19B084"); 
				String plaintext = Decrypt(ciphertext, IV);
				String test = Encrypt(plaintext.getBytes(StandardCharsets.UTF_8), IV);
				long EndTime = System.currentTimeMillis();
				System.out.println("\nPlaintext is: " + plaintext + "\nCiphertext: " + test + "\nKey: " + IV);
				System.out.println("Execution Time: " + (EndTime - StartTime)/ 1000.0 + " seconds");
				break;
			default:
				System.out.println("Invalid choice!");
				break;
			}
		}while(true);
		
	}
	
	/*Gets the remaining bits for the key
	 * Takes the IV and current iteration of the key
	 * Returns the full 32-bit key
	 * */
	private static String getKey(String Partialkey, long restOfkey){
		String Completekey = "";
		String pad = "";
		int len = 32 - Partialkey.length();
		
		if(len == 4){ //file 1
			pad = String.format("%04X", restOfkey );
		}else if(len == 6){ //file 2
			pad = String.format("%06X", restOfkey);
		}else if(len == 8){ //file 3
			pad = String.format("%08X", restOfkey);
		}else if(len == 10){ //file 4
			pad = String.format("%010X", restOfkey);
		}else{ //Shouldn't happen for this assignment
			System.out.println("LOL WHAT HAPPENED??");
			System.exit(0);
		}
		
		Completekey = Partialkey.concat(pad);
		
		return Completekey;
	}
	
	/*Check the given decrypted text for English text 
	 * English text is defined as Alphabetic Characters [a-zA-z] including spaces
	 * Punctuation comma(,) dot(.)
	 * Numbers 0-9
	 * Returns true if it is English, false otherwise
	 **/
	private static boolean isEnglishChars(String decryptedText){
		Pattern pattern = Pattern.compile("^[ a-zA-Z0-9.,]{1,}"); 
		Matcher match = pattern.matcher(decryptedText);

		boolean matchFound = false;
		int textlen = decryptedText.length();
		int matchSize = 0;
		
		while(match.find()){
			matchFound = true;
			matchSize = match.end();
		}
		
		if(!match.find() && (matchSize != textlen)){
			matchFound = false;
		}
		
		return matchFound;
	}
	/*Decryption method 
	 * @param byte array ciphertext
	 * @param string key - IV
	 * 
	 * @return A decrypted ciphertext - plaintext 
	 * */
	private static String Decrypt(byte[] ciphertext, String IV){
		
		String plaintext = "";
		
		BlockCipherPadding padding = new ZeroBytePadding();
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AESEngine(), padding);
		
		KeyParameter key = new KeyParameter(Hex.decode(IV));
		cipher.init(false, key);
		
		byte[] buffer = new byte[cipher.getOutputSize(ciphertext.length)];
		
		int length = cipher.processBytes(ciphertext, 0, ciphertext.length, buffer, 0);
		try {
			
			length += cipher.doFinal(buffer,  length);
			
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			e.printStackTrace();
		}
				
		plaintext = new String((Arrays.copyOf(buffer, length)), StandardCharsets.UTF_8);
		
		return plaintext;
	}
	
	/*Encryption test in order to test decryption method
	 *@param plaintext string
	 *@param a key IV
	 *@return a ciphertext encoded in Hex
	 */
	private static String Encrypt(byte[] plaintext, String IV){
		String ciphertext = null;
		
		BlockCipherPadding padding = new ZeroBytePadding();
		BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new AESEngine(), padding);
		
		KeyParameter key = new KeyParameter(Hex.decode(IV));
		cipher.init(true, key);
		
		byte[] buffer = new byte[cipher.getOutputSize(plaintext.length)];
		
		int length = cipher.processBytes(plaintext, 0, plaintext.length, buffer, 0);
		try {
			length += cipher.doFinal(buffer,  length);
		} catch (DataLengthException | IllegalStateException | InvalidCipherTextException e) {
			
			e.printStackTrace();
		}
				
		ciphertext = new String(Hex.encode((Arrays.copyOf(buffer, length)))).toUpperCase();
				
		return ciphertext;
	}
	
	/* The only method called from main
	 * Determines which the size of the key passed to it, adds the appropiate padding
	 * calls getKey, Decrypt, IsEnglishChars and FileWriter methods
	 * @return nothing
	 */
	public static void cipher(String cipher, String IVfile){
		long StartTime = System.currentTimeMillis();
		String plaintext = "";
		String key = "";
		String Cipherfile = "";
		long restOfkey = 0L;
		byte[] buf = new byte[16]; 
		
		byte[] ciphertext = Hex.decode(cipher); 
		
		int bytesRead = 16;
		long   limit = 0L;
		int IVfile_len = 32 - IVfile.length();
		
		key = getKey(IVfile, restOfkey);
		
		if(IVfile_len == 4){ //file 1, key = 639404CBD1A1BD2322B206C39140EC18
			limit = 0xFFFF;
			Cipherfile = "Cipherfile1";
		}else if(IVfile_len == 6){ //file 2, key = F806274AC0B446C18725ABDCE56F1A72
			limit = 0xFFFFFF;
			Cipherfile = "Cipherfile2";
		}else if(IVfile_len == 8){ //file 3, key = 0AA4A910D451E069611D5571CCF032F2
			limit= 0xFFFFFFFFL;
			Cipherfile = "Cipherfile3";
		}else if(IVfile_len == 10){ //file 4, key = 9D0B180B5CD9DC074ACB0E7981575304

			limit = 0xFFFFFFFFFFL;
			Cipherfile = "Cipherfile4";
		}
		else{ //Shouldn't happen with for this assignment
			System.out.println("LOL WHAT HAPPENED??");
			System.exit(0);
		}
		
		
		while(restOfkey <= limit && (bytesRead <= ciphertext.length) ){ //FF = 1 byte, FF FF = 2 bytes
			System.out.println(key);
			buf = Arrays.copyOfRange(ciphertext, bytesRead - 16, bytesRead); //copy the first 2 bytes of the ciphertext
			
			String decryptedText = Decrypt(buf, key);
			
			if(isEnglishChars(decryptedText)){
				
				plaintext = plaintext.concat(decryptedText);
				bytesRead += 16;
				
				
			}
			else {//should only call key if it's bad
				restOfkey +=1;
				bytesRead = 16;
				key = getKey(IVfile, restOfkey);
				
			}
		}
		
		long EndTime = System.currentTimeMillis();
		long TimeTaken = EndTime - StartTime;
		
		if(plaintext.length()!= 0){
			fileWriter(Cipherfile, plaintext, key, TimeTaken);
			System.out.println("\nThe plaintext is: \"" + plaintext + "\" found with key: \"" + key + "\"");
		}else{
			System.out.println("No keys found.");
		}
		
		System.out.println("Execution time: " + (TimeTaken / 1000.0) + " seconds");
		
		return;
	}
	
	/*Writes the results to a file. 
	 * @param Cipherfile - for knowing which file was decrypted
	 * @param plaintext
	 * @param key
	 * @return nothing
	 * */
	private static void fileWriter(String Cipherfile, String plaintext, String key, long TimeTaken){
		
		BufferedWriter writer = null;
		BufferedReader reader = null;
		File file = new File("DecryptedText.txt");
		
		if(!file.exists()){
			try {
				file.createNewFile();
				writer = new BufferedWriter(new FileWriter("DecryptedText.txt", true));
				reader = new BufferedReader(new FileReader("DecryptedText.txt"));
			} catch (IOException e) {
				
				e.printStackTrace();
			}
		}else{
			try {
				writer = new BufferedWriter(new FileWriter("DecryptedText.txt", true));
				reader = new BufferedReader(new FileReader("DecryptedText.txt"));
			} catch (IOException e) {
				
				e.printStackTrace();
			}
		}
		
		try {
			@SuppressWarnings("unused")
			String line;
			if( (line = reader.readLine() ) != null){
				writer.newLine();
				writer.write(Cipherfile + ": " + "The Plaintext is \"" + plaintext + "\" & the Key is " + key);
				writer.newLine();
				writer.write("Execution Time: " + (TimeTaken / 1000.0) + " seconds");
				writer.newLine();
			}else 
				writer.write(Cipherfile + ": " + "The Plaintext is \"" + plaintext + "\" & the Key is " + key);
				writer.newLine();
		} catch (IOException e) {
			
			e.printStackTrace();
		}
		finally {
			
			try {
				writer.flush();
				writer.close();
				reader.close();
			} catch (IOException e) {
				
				e.printStackTrace();
			}
			
		}
	}
}