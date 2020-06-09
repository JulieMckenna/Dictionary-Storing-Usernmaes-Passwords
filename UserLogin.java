/**
 * A program to read in and modify password files using salted SHA-512 hashes
 */
//package edu.wit.cs.comp2000;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Scanner;

public class UserLogin {

	static Hashtable<String, Password> userTable = new Hashtable<>();// stores all relevant info about authentication
	private static final Random RandomObj = new SecureRandom();
	
	/**
	 * Reads lines from the userFile, parses them, and adds the results to the userTable
	 * 
	 * @param userFile A File object to read from
	 * @throws IOException 
	 */
	private static void AddUsersToTable(File userFile) throws IOException {
		BufferedReader scan = new BufferedReader(new FileReader(userFile));
		String user = scan.readLine();
		
		while(user != null)
		{
			int count = 0;
			String username = null, usersalt = null, hash = null;	
			int lastcolon = 0;
			for(int i = 0; i < user.length(); i++)
			{
				if(user.charAt(i) == ':')
				{
					if(count == 0)
					{
						username = user.substring(0, i);
						//System.out.println(username);
						count++;
						lastcolon = i;
					}
					else if(count == 1)
					{
						usersalt = user.substring(lastcolon + 1, i);
						count++;
						lastcolon = i;
						hash = user.substring(lastcolon + 1, user.length());
					}
				}
			}
			Password userpass = new Password(hash, usersalt); 
			//System.out.println(username + usersalt + hash);
			userTable.put(username, userpass);
			user = scan.readLine();
		}
		scan.close();
	}

	/**
	 * Iterates through all key values in userTable and outputs lines
	 * to userFile formatted like user:salt:hash
	 * 
	 * @param userFile A File object that the table should be written to
	 * @throws IOException 
	 */
	private static void WriteFile(File userFile) throws IOException  {
	
		if(userTable.isEmpty())
		{
			return;
		}
		BufferedWriter write = new BufferedWriter(new FileWriter(userFile));
		
		List<String> tempList = new ArrayList<>();
		for(Entry<String, Password> e : userTable.entrySet()) {
			String saltedHashed = String.format("%s:%s:%s", e.getKey(), e.getValue().getSalt(), e.getValue().getHash());
			tempList.add(saltedHashed);
			write.write(saltedHashed);
			write.write("\n");
		}
		write.close();
	}

	
	/**
	 * Prompts the user for a username/password and attempts to add the user
	 * to the userTable. Fails if the user is already present in the table.
	 * 
	 * @param s A Scanner to read from the console
	 * @return boolean based on if the user credentials are added to table
	 */
	private static boolean AddUser(Scanner s) {
		boolean added;
		System.out.println("Please enter a user name");
		String username = s.nextLine();
		
		if(userTable.containsKey(username)) {
			System.out.println("There is already a user with that username in the data base");
			added = false;
		}
		else
		{
			System.out.println("Please enter your password");
			String pass = s.nextLine();
			String saltpass = "aaaa" + pass;
			String hash = genHash(saltpass);
			String salt = genSalt();
			Password userpass = new Password(hash, salt); 
			userTable.put(username, userpass);
			added = true;
		}
			return added;
	}
	

	/**
	 * Prompts the user for a username/password and checks the userTable for
	 * the resulting combination
	 * 
	 * @param s A Scanner to read from the console
	 * @return boolean based on if the user credentials are accurate
	 */
	private static boolean Login(Scanner s) {
		System.out.println("Please enter your username");
		String username = s.next();
		boolean logedin = false;
		
		if(userTable.containsKey(username))
		{
			System.out.println("Please enter your password");
			String userpass = s.next();
			String saltpass = ("aaaa"+userpass);
			String hash = genHash(saltpass);
		
			if(hash.equals(userTable.get(username).getHash()))
				logedin = true;
				
		}
		else {
			System.out.println("That user is not in the system");
		}
		return logedin;
	}


	/**
	 * Generates a salt value based on the SecureRandom object
	 * 
	 * @return Returns an 8-character string that represents a random value
	 */
	private static String genSalt() {
		// TODO Auto-generated method stub
		byte[] salt = new byte[8];
		RandomObj.nextBytes(salt);
		return byteArrayToStr(salt);
	}
	
	/**
	 * Converts an array of bytes to the corresponding hex String
	 * 
	 * @param b An array of bytes
	 * @return A String that represents the array of bytes in hex
	 */
	private static String byteArrayToStr(byte[] b) {
		StringBuffer hexHash =  new StringBuffer();
		for (int i = 0; i < b.length; i++)
		{
			String hexChar = Integer.toHexString(0xff & b[i]);
			if (hexChar.length() == 1)
			{
				hexHash.append('0');
			} // end if
			hexHash.append(hexChar);
		} // end for
		return hexHash.toString();
	}

	/**
	 * Generates a hash for a given String
	 * 
	 * @param p A String to calculate the hash from
	 * @return The hash value as a String
	 */
	private static String genHash(String p) {
		// Create the MessageDigest object
		MessageDigest myDigest = null;
		try {
			myDigest = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			System.err.println("SHA-512 not available");
			System.exit(1);
		}
		// Update the object with the hash of â€˜someStringToHashâ€™
		myDigest.update(p.getBytes());
		
		// Get the SHA-512 hash from the object
		byte hashCode[] = myDigest.digest();

		return byteArrayToStr(hashCode);
	}

	
	public static void main(String[] args) throws IOException  {

		Scanner s = new Scanner(System.in);

		System.out.print("Enter user file: ");
		File userFile = new File(s.nextLine());
		AddUsersToTable(userFile);

		while (1==1) {
			System.out.print ("Would you like to (L)og in, (A)dd a new user, or (Q)uit? ");
			char choice = s.nextLine().charAt(0);

			switch (choice) {
			case 'L':
				{if (Login(s))
					System.out.println("Login successful.");
				else
					System.out.println("Username and password did not match.");
				break;}
			case 'A':
				if (AddUser(s))
					System.out.println("User successfully added.");
				else
					System.out.println("User not added.");
				break;
			case 'Q':
				WriteFile(userFile);
				s.close();
				System.out.println("Exiting.");
				System.exit(0);
			}
		}

	}

}
