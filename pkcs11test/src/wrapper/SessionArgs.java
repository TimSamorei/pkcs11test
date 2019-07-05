package wrapper;


public class SessionArgs {
	
	private LongWrapper key = null;
	private LongWrapper mechanism = null;
	private boolean encUpdateCalled = false;
	private boolean decUpdateCalled = false;
	private boolean decInit = false;
	private boolean encInit = false;
	private byte[] encbuffer;
	private byte[] decbuffer;
	
	public LongWrapper getMechanism() {
		return mechanism;
	}
	public void setMechanism(LongWrapper mechanism) {
		this.mechanism = mechanism;
	}
	public LongWrapper getKey() {
		return key;
	}
	public void setKey(LongWrapper key) {
		this.key = key;
	}
	public boolean isEncUpdateCalled() {
		return encUpdateCalled;
	}
	public void setEncUpdateCalled(boolean encUpdateCalled) {
		this.encUpdateCalled = encUpdateCalled;
	}
	public boolean isDecUpdateCalled() {
		return decUpdateCalled;
	}
	public void setDecUpdateCalled(boolean decUpdateCalled) {
		this.decUpdateCalled = decUpdateCalled;
	}
	public byte[] getEncbuffer() {
		return encbuffer;
	}
	public void setEncbuffer(byte[] encbuffer) {
		this.encbuffer = encbuffer;
	}
	public byte[] getDecbuffer() {
		return decbuffer;
	}
	public void setDecbuffer(byte[] decbuffer) {
		this.decbuffer = decbuffer;
	}
	public boolean isDecInit() {
		return decInit;
	}
	public void setDecInit(boolean decInit) {
		this.decInit = decInit;
	}
	public boolean isEncInit() {
		return encInit;
	}
	public void setEncInit(boolean encInit) {
		this.encInit = encInit;
	}
}
