package wrapper;

public class LongWrapper {

	private long value;
	
	public LongWrapper(long value) {
		this.value = value;
	}
	
	public void set(long value) {
		this.value = value;
	}
	
	public long get() {
		return value;
	}
}
