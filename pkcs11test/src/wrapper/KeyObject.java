package wrapper;

public class KeyObject {

	long session;
	CK_ATTRIBUTE[] pTemplate;
	
	public KeyObject(long session , CK_ATTRIBUTE[] pTemplate) {
		this.session = session;
		this.pTemplate = pTemplate;
	}
	
}
