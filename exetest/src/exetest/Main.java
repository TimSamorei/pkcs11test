package exetest;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class Main {
	
	private static final byte[] AID_ANDROID = { (byte)0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	private static final byte[] CLA_INS_P1_P2 = { 0x00, (byte)0xA4, 0x04, 0x00 };
	private static final short SW_SUCCESS = (short) 0x9000;
    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_GETSIGNATURE = (byte) 0xA0;
    private final static byte INS_GETCERT = (byte) 0xB0;
    private final static byte INS_GETDATA = (byte) 0xC0;
    private final static byte INS_ENCRYPT = (byte) 0xD0;
    
    static byte[] responseData;
    static int responseLength;
    static String request;
	
    static CardChannel channel;
    
    private static SecretKeySpec secretKey;
    private static byte[] key;
    
	public static void main(String[] args) {
		
		mockEncryption(args[0], args[1]);
		
	}

	private static void getData(byte[] destination, String dataType, int dataLength) {
		try {
		int counter = 0;
		CommandAPDU cmd;
		ResponseAPDU response;
		byte[] data;
		String request;
		while (responseLength > 200) {
			request = dataType + "#" + "200" + "#" + counter;
			cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, request.getBytes("ASCII"));
			response = transmit(channel, cmd);
			checkSW(response);
			data = response.getData();
			System.arraycopy(data, 0, destination, counter*200, 200);
			responseLength = responseLength - 200;
			counter++;
		}
		request = dataType + "#" + responseLength + "#" + counter;
		cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, request.getBytes("ASCII"));
		response = transmit(channel, cmd);
		checkSW(response);
		data = response.getData();
		System.arraycopy(data, 0, destination, counter*200, responseLength);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static Card waitForCard(CardTerminals terminals)
            throws CardException {
        while (true) {
            for (CardTerminal ct : terminals
                    .list(CardTerminals.State.CARD_INSERTION)) {

                return ct.connect("*");
            }
            terminals.waitForChange();
        }
    }
	
    private static ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
    	System.out.println("APDU sent: " + toHex(cmd.getBytes()));
        ResponseAPDU response = channel.transmit(cmd);
 
        return response;
    }
    
    private static void checkSW(ResponseAPDU response) {
        if (response.getSW() != (SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X. Exiting.\n",
                    response.getSW());
            System.exit(1);
        } else {
        	logResponse(response);
        }
    }
    
    private static byte[] createSelectAidApdu(byte[] aid) {
		byte[] result = new byte[6 + aid.length];
		System.arraycopy(CLA_INS_P1_P2, 0, result, 0, CLA_INS_P1_P2.length);
		result[4] = (byte)aid.length;
		System.arraycopy(aid, 0, result, 5, aid.length);
		result[result.length - 1] = 0;
		return result;
	}
    
    private static String toHex(byte[] bytes) {
        StringBuilder buff = new StringBuilder();
        for (byte b : bytes) {
            buff.append(String.format("%02X", b));
        }

        return buff.toString();
    }

    private static void logResponse(ResponseAPDU response) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("APDU received: %s %s (%d)\n", toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("APDU received: %s\n", swStr);
        }
    }
    
    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
    
    public static String encrypt(String data, String alias, String mechanism) {
		try {
			TerminalFactory factory = TerminalFactory.getDefault();
			CardTerminals terminals = factory.terminals();
			if (terminals.list().isEmpty()) {
				System.err.println("No smart card reders found. Connect reader and try again.");
				System.exit(1);
			}
			System.out.println("Place phone/card on reader to start");
			Card card = waitForCard(terminals);
			System.out.println("Card found");
			card.beginExclusive();
        
			try {
				// Select Applet
				channel = card.getBasicChannel();
				CommandAPDU cmd = new CommandAPDU(createSelectAidApdu(AID_ANDROID));
				ResponseAPDU response = transmit(channel, cmd);
				checkSW(response);
				
				// Send Encryption Request
				request = data + "#" + alias + "#" + mechanism;
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_ENCRYPT, 0x00, 0x00, request.getBytes("ASCII"));
				response = transmit(channel, cmd);
				checkSW(response);
				responseData = response.getData();
				
				// Get Encrypted Data
				responseLength = new Integer(new String(responseData));
				byte[] encrypteddata = new byte[responseLength];
				getData(encrypteddata, "encryption", responseLength);
				
				return new String(encrypteddata);
			} finally {
                card.endExclusive();
                card.disconnect(false);
            }
		} catch (Exception e) {
			throw new RuntimeException(e);
        }
    }
    
	
	private static void mockEncryption(String strToEncrypt, String secret) {
        try
        {
        	//System.out.println("DATA: " + strToEncrypt);
        	//System.out.println("KEY: " + secret);
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(strToEncrypt.getBytes());
            
            BASE64Encoder myEncoder = new BASE64Encoder();
            String encryptedstring = myEncoder.encode(encrypted);
            
            System.out.println(encryptedstring);
            //testMockEncryption(encryptedstring);
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
    }

	private static void testMockEncryption(String encryptedstring) {
		try {
			// der verschl. Text
			String geheim = encryptedstring;
		 
			// BASE64 String zu Byte-Array konvertieren
			BASE64Decoder myDecoder2 = new BASE64Decoder();
			byte[] crypted2 = myDecoder2.decodeBuffer(geheim);
		 
			// Entschluesseln
			Cipher cipher2 = Cipher.getInstance("AES");
			cipher2.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] cipherData2 = cipher2.doFinal(crypted2);
			String erg = new String(cipherData2);
		 
			// Klartext
			System.out.println("TEST: " + erg);
		}
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
	}
}
