package wrapper;

import java.util.concurrent.atomic.AtomicLong;

public class SessionArgs {
	
	private AtomicLong key = null;
	private AtomicLong mechanism = null;
	private boolean encUpdateCalled = false;
	private boolean decUpdateCalled = false;
	private byte[] encbuffer;
	private byte[] decbuffer;
	
	public AtomicLong getMechanism() {
		return mechanism;
	}
	public void setMechanism(AtomicLong mechanism) {
		this.mechanism = mechanism;
	}
	public AtomicLong getKey() {
		return key;
	}
	public void setKey(AtomicLong key) {
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
}
