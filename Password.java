//package edu.wit.cs.comp2000;

public class Password {
	String hash;
	String salt;
	
	public Password(String h, String s) {
		hash = h;
		salt = s;
	}
	
	public String getSalt() {
		return salt;
	}
	
	public String getHash() {
		return hash;
	}
	
	
}
