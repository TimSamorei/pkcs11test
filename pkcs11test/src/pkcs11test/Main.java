package pkcs11test;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import sun.misc.BASE64Encoder;
import wrapper.CK_ATTRIBUTE;
import wrapper.CK_MECHANISM;
import wrapper.KeyObject;
import wrapper.LongWrapper;
import wrapper.PKCS11;
import wrapper.PKCS11Exception;

public class Main {
	
	private static final byte[] AID_ANDROID = { (byte)0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	private static final byte[] CLA_INS_P1_P2 = { 0x00, (byte)0xA4, 0x04, 0x00 };
	private static final short SW_SUCCESS = (short) 0x9000;
    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_GETSIGNATURE = (byte) 0xA0;
    private final static byte INS_GETCERT = (byte) 0xB0;
    private final static byte INS_GETDATA = (byte) 0xC0;
    private final static byte INS_ENCRYPT = (byte) 0xD0;
	private final static byte INS_DECRYPT = (byte) 0xE0;
    
    static byte[] responseData;
    static int responseLength;
    static byte[] reqData;
	
    static CardChannel channel;
    
    
	public static void main(String[] args) {
		
		//Data to call
		long session;
		long key = 4;
		CK_MECHANISM mechanism = new CK_MECHANISM(123);
		
		byte[] data;
		data = "Houston wir haben ein Problem".getBytes();
		
		byte[] encdata = new byte[data.length];
		
		LongWrapper enclength = new LongWrapper(1);
		LongWrapper phSession = new LongWrapper(1);
		LongWrapper phKey = new LongWrapper(1);
		
		PKCS11 token = PKCS11.getInstance();
		try {
			System.out.println("Open Session: " + token.C_OpenSession(0, 0, null, null, phSession));
			session = phSession.get();
			System.out.println("PLAINTEXT BEFORE: " + new String(data));
			
			token.C_EncryptInit(session, mechanism, key);
			System.out.println("Code: " + token.C_Encrypt(session, data, (long)data.length, encdata, enclength));
			encdata = new byte[(int) enclength.get()];
			System.out.println("Code: " + token.C_Encrypt(session, data, (long)data.length, encdata, enclength));
			
			data = new byte[encdata.length];
			for (int i = 0; i < encdata.length; i++) data[i] = encdata[i];
			encdata = new byte[1];
			
			token.C_DecryptInit(session, mechanism, key);
			System.out.println("Code: " + token.C_Decrypt(session, data, (long)data.length, encdata, enclength));
			encdata = new byte[(int) enclength.get()];
			System.out.println("Code: " + token.C_Decrypt(session, data, (long)data.length, encdata, enclength));
			
			
			System.out.println("Close Session: " + token.C_CloseSession(session));
			System.out.println("--- RESULTS ---");
			System.out.println("PLAINTEXT AFTER: " + new String(encdata));
			System.out.println("ENCRYPTEDTEXT: " + new String(data));
			System.out.println("ENCRYPTEDHEX: " + toHex(data));
			
			
		} catch (PKCS11Exception e) {
			System.out.println("ERROR");
		}
		
	}
	
	
	
	
	private static void getData(byte[] destination, String dataType, int dataLength) {
		try {
		int counter = 0;
		CommandAPDU cmd;
		ResponseAPDU response;
		byte[] data;
		while (responseLength > 200) {
			reqData = packReqData(dataType.getBytes(), "200".getBytes(), ("" +counter).getBytes());
			cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, reqData);
			response = transmit(channel, cmd);
			checkSW(response);
			data = response.getData();
			System.arraycopy(data, 0, destination, counter*200, 200);
			responseLength = responseLength - 200;
			counter++;
		}
		reqData = packReqData(dataType.getBytes(), ("" +responseLength).getBytes(), ("" +counter).getBytes());
		cmd = new CommandAPDU(PKI_APPLET_CLA, INS_GETDATA, 0x00, 0x00, reqData);
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
    
    public static byte[] encrypt(byte[] data, long key, long mechanism) {
		try {
			
			Card card = openConnection();
			try {
				channel = card.getBasicChannel();
				CommandAPDU cmd;
				ResponseAPDU response;
				
				// Select Applet
				selectApplet();
				
				// Send Encryption Request
				reqData = packReqData(data, ("" +key).getBytes(), ("" +mechanism).getBytes());
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_ENCRYPT, 0x00, 0x00, reqData);
				response = transmit(channel, cmd);
				checkSW(response);
				responseData = response.getData();
				
				// Get Encrypted Data
				responseLength = new Integer(new String(responseData));
				byte[] encrypteddata = new byte[responseLength];
				getData(encrypteddata, "encryption", responseLength);
				
				return encrypteddata;
			} finally {
                card.endExclusive();
                card.disconnect(false);
            }
		} catch (Exception e) {
			throw new RuntimeException(e);
        }
    }
    
    public static byte[] decrypt(byte[] data, long key, long mechanism) {
		try {
			
			Card card = openConnection();
			try {
				channel = card.getBasicChannel();
				CommandAPDU cmd;
				ResponseAPDU response;
				
				// Select Applet
				selectApplet();
				
				// Send Encryption Request
				reqData = packReqData(data, ("" +key).getBytes(), ("" +mechanism).getBytes());
				cmd = new CommandAPDU(PKI_APPLET_CLA, INS_DECRYPT, 0x00, 0x00, reqData);
				response = transmit(channel, cmd);
				checkSW(response);
				responseData = response.getData();
				
				// Get Encrypted Data
				responseLength = new Integer(new String(responseData));
				byte[] encrypteddata = new byte[responseLength];
				getData(encrypteddata, "decryption", responseLength);
				
				return encrypteddata;
			} finally {
                card.endExclusive();
                card.disconnect(false);
            }
		} catch (Exception e) {
			throw new RuntimeException(e);
        }
    }
    
    private static byte[] packReqData(byte[] data1, byte[] data2, byte[] data3) {
		byte[] ret = new byte[data1.length+data2.length+data3.length+2];
		
		System.arraycopy(data1, 0, ret, 0, data1.length);
		System.arraycopy("#".getBytes(), 0, ret, data1.length, 1);
		System.arraycopy(data2, 0, ret, data1.length+1, data2.length);
		System.arraycopy("#".getBytes(), 0, ret, data1.length+data2.length+1, 1);
		System.arraycopy(data3, 0, ret, data1.length+data2.length+2, data3.length);

		return ret;
	}

	private static void selectApplet() throws CardException {
    	CommandAPDU cmd = new CommandAPDU(createSelectAidApdu(AID_ANDROID));
		ResponseAPDU response = transmit(channel, cmd);
		checkSW(response);
	}

	private static Card openConnection() throws CardException {
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
		return card;
	}

	public static byte[] mockEncryption(byte[] data, long key, long mechanism) {
    	byte[] returnV = new byte[data.length];
    	for (int i = 0; i < data.length; i++) {
    		returnV[i] = (byte) ((int)data[i] ^ (int)1);
    	}
    	
    	return returnV;
    }
    
    public static byte[] mockDecryption(byte[] data, long key, long mechanism) {
    	byte[] returnV = new byte[data.length];
    	for (int i = 0; i < data.length; i++) {
    		returnV[i] = (byte) ((int)data[i] ^ (int)1);
    	}
    	
    	return returnV;
    }

	public static KeyObject mockGenerateKey(long hSession, CK_ATTRIBUTE[] pTemplate) {
		return new KeyObject(hSession, pTemplate);
	}

	public static KeyObject[] mockGenerateKeyPair(long hSession, CK_ATTRIBUTE[] pPublicKeyTemplate,
			CK_ATTRIBUTE[] pPrivateKeyTemplate) {
		KeyObject[] keys = {new KeyObject(hSession, pPublicKeyTemplate), new KeyObject(hSession, pPrivateKeyTemplate)};
		return keys;
	}
}
