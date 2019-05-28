package sepkiclient;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class Main {
	
    // AID: A0 00 00 00 01 01 01 (probably not unique...)
    private static final byte[] SELECT_PKI_APPLET_CMD = { 0x00, (byte) 0xA4,
            0x04, 0x00, 0x06, (byte) 0xA1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };
    
    private static final byte[] CLA_INS_P1_P2 = { 0x00, (byte)0xA4, 0x04, 0x00 };
    private static final byte[] AID_ANDROID = { (byte)0xA1, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 };

    private static final short SW_SUCCESS = (short) 0x9000;

    private final static byte PKI_APPLET_CLA = (byte) 0x80;
    private final static byte INS_VERIFY_PIN = (byte) 0x01;
    private final static byte INS_SIGN = (byte) 0x02;

    public static void main(String[] args) {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            CardTerminals terminals = factory.terminals();
            if (terminals.list().isEmpty()) {
                System.err
                        .println("No smart card reders found. Connect reader and try again.");
                System.exit(1);
            }

            System.out.println("Place phone/card on reader to start");
            Card card = waitForCard(terminals);
            System.out.println("Card found");
            card.beginExclusive();

            try {
            	System.out.println("Before BasicChannel");
                CardChannel channel = card.getBasicChannel();
                System.out.println("Before APDU Creation: old one - " + "00A4040006A1111111111111");
                CommandAPDU cmd = new CommandAPDU(createSelectAidApdu(AID_ANDROID));
                System.out.println("Before transmission");
                ResponseAPDU response = transmit(channel, cmd);
                System.out.println("Before checking SW");
                checkSW(response);
                System.out.println("After response");

                String pin = "123";
                cmd = new CommandAPDU(PKI_APPLET_CLA, INS_VERIFY_PIN, 0x0, 0x0,
                        pin.getBytes("ASCII"));
                response = transmit(channel, cmd);
                checkSW(response);

                byte[] signedData = "sign me!".getBytes("ASCII");
                cmd = new CommandAPDU(PKI_APPLET_CLA, INS_SIGN, 0x0, 0x0,
                        signedData);
                response = transmit(channel, cmd);
                checkSW(response);

                byte[] signature = response.getData();
                System.out.println();
                System.out.printf("Got signature from card: %s\n",
                        toHex(signature));

                if (args.length > 1) {
                    String certPath = args[1].trim();
                    System.out
                            .printf("Will use certificate from '%s' to verify signature\n",
                                    certPath);
                    byte[] certBlob = readFile(certPath);
                    CertificateFactory cf = CertificateFactory
                            .getInstance("X509");
                    X509Certificate cert = (X509Certificate) cf
                            .generateCertificate(new ByteArrayInputStream(
                                    certBlob));
                    System.out.println("\tIssuer: "
                            + cert.getIssuerDN().getName());
                    System.out.println("\tSubject: "
                            + cert.getSubjectDN().getName());
                    System.out.println("\tNot Before: " + cert.getNotBefore());
                    System.out.println("\tNot After: " + cert.getNotAfter());
                    System.out.println();

                    Signature s = Signature.getInstance("SHA1withRSA");
                    s.initVerify(cert);
                    s.update(signedData);
                    boolean valid = s.verify(signature);
                    System.out.printf("Signature is valid: %s\n", valid);
                }
            } finally {
                card.endExclusive();
                card.disconnect(false);
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
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

	private static void usage() {
        System.out.println("se-pki-client <PIN> [certificate file]");
        System.exit(1);
    }

    private static byte[] readFile(String filename) throws Exception {
        File f = new File(filename);
        byte[] result = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        try {
            in.read(result);

            return result;
        } finally {
            in.close();
        }
    }

    private static void checkSW(ResponseAPDU response) {
        if (response.getSW() != (SW_SUCCESS & 0xffff)) {
            System.err.printf("Received error status: %02X. Exiting.\n",
                    response.getSW());
            System.exit(1);
        }
    }

    private static ResponseAPDU transmit(CardChannel channel, CommandAPDU cmd)
            throws CardException {
    	System.out.println("APDU: " + toHex(cmd.getBytes()));
        ResponseAPDU response = channel.transmit(cmd);
        log(response);

        return response;
    }

    private static void log(CommandAPDU cmd) {
        System.out.printf("--> %s\n", toHex(cmd.getBytes()),
                cmd.getBytes().length);
    }

    private static void log(ResponseAPDU response) {
        String swStr = String.format("%02X", response.getSW());
        byte[] data = response.getData();
        if (data.length > 0) {
            System.out.printf("<-- %s %s (%d)\n", toHex(data), swStr,
                    data.length);
        } else {
            System.out.printf("<-- %s\n", swStr);
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

    public static String toHex(byte[] bytes) {
        StringBuilder buff = new StringBuilder();
        for (byte b : bytes) {
            buff.append(String.format("%02X", b));
        }

        return buff.toString();
    }

}
