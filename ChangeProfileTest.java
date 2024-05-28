/*Homework 2: Implement the secure communication diagram with application classes and six security classes
 * 
 * Christian Tran - R#11641653
 * 
 * This program implements a secure communication diagram model and attempts to implement the security classes as well
 * as the application classes
 * 
 * */

import javax.crypto.KeyGenerator; //Import key generator to generate a secret key
import javax.crypto.SecretKey; //Import secret key object
import javax.crypto.Cipher; //Import the cipher to encrypt the secret key (this time we'll do AES)
import java.util.Scanner; //Import the Scanner for user input
import java.util.Random; // Import random to generate a random number for security code


//Class that encrypts with a given secret key. NOTE: WE ARE NOT USING KEY PAIRS (NO PUBLIC KEY AND NO PRIVATE KEY NEEDED) or a DIGITAL SIGNATURE
class Encryption
{
	static byte[] encrypt(byte s[], Cipher c, SecretKey sk) throws Exception
	{
		c.init(Cipher.ENCRYPT_MODE, sk);
		return c.doFinal(s);
	}
}

//Class that decrypts with a given secret key.
class Decryption{
	static byte[] decrypt(byte s[], Cipher c, SecretKey sk) throws Exception
	{
		c.init(Cipher.DECRYPT_MODE, sk);
		return c.doFinal(s);
	}
}


//Application Class that is used to represent the Customer's profile
class CustomerProfile
{
	//The security code from 
	private static String SecurityCode; //An integer that represents the security code generated
	private static SecretKey secret_key; //The secret key given to this account
	private static Cipher profileCipher; //The profile's cipher used to decrypt the account
	/*It looks like the communication diagram creates the security code, then encrypts it with the secret key,
	 * then sends it to the cell phone (which decrypts the security code) then verifies if the customer enters the correct (decrypted) security code
	 * then it sends a "valid" message to the customer's profile to be viewed, then hides the sensitive profile information,
	 * then displays the profile out.
	*/
	
	//Basic customer profile information 
	private static String name;
	private static String address;
	private static String phone_num;
	private static String email;
	private static byte[] encrypted_name;
	private static byte[] encrypted_address;
	private static byte[] encrypted_phone_num;
	private static byte[] encrypted_email;
	
	//Set methods for setting the attributes of Customer profile
	static void setName (String input_name) {
		name = input_name;
	}
	
	static void setAddress (String input_addr) {
		address = input_addr;
	}
	
	static void setPhoneNum (String input_phone_num) {
		phone_num = input_phone_num;
	}
	
	static void setEmail (String input_email) {
		email = input_email;
	}
	
	static void setSecCode (String input_sec_code){
		SecurityCode = input_sec_code;
	}
	
	static void setSecKey (SecretKey input_sk) {
		secret_key = input_sk;
	}
	
	static void setProfileCipher(Cipher aesCipher) {
		profileCipher = aesCipher;
	}
	
	static void setEncryptedName(byte[] input_name) {
		encrypted_name = input_name;
	}
	
	static void setEncryptedAddress(byte[] input_addr) {
		encrypted_address = input_addr;
	}
	
	static void setEncryptedPhoneNum(byte[] input_phone) {
		encrypted_phone_num = input_phone;
	}
	
	static void setEncryptedEmail(byte[] input_email) {
		encrypted_email = input_email;
	}
	
	//Get methods for getting the individual attribute variable
	static String getName () {
		return name;
	}
	
	static String getAddress () {
		return address;
	}
	
	static String getPhoneNum () {
		return phone_num;
	}
	
	static String getEmail () {
		return email;
	}
	
	static String getSecCode() {
		return SecurityCode;
	}
	
	static SecretKey getSecKey () {
		return secret_key;
	}
	
	static Cipher getProfileCipher() {
		return profileCipher;
	}
	
	static byte[] getEncryptedName() {
		return encrypted_name;
	}
	
	static byte[] getEncryptedAddress() {
		return encrypted_address;
	}
	
	static byte[] getEncryptedPhoneNum() {
		return encrypted_phone_num;
	}
	
	static byte[] getEncryptedEmail() {
		return encrypted_email;
	}
	
	
	
	
	
	//Encrypts the user information in profile
	static void encryptProfile() {
		try {
			//Convert all of the profile information into byte arrays
			byte[] name_cleartext = name.getBytes();
			byte[] address_cleartext = address.getBytes();
			byte[] phone_num_cleartext = phone_num.getBytes();
			byte[] email_cleartext = email.getBytes();
		
			//Encrypt the profile information:
			byte[] name_ciphertext = Encryption.encrypt(name_cleartext, profileCipher, secret_key);
			byte[] address_ciphertext = Encryption.encrypt(address_cleartext, profileCipher, secret_key);
			byte[] phone_num_ciphertext = Encryption.encrypt(phone_num_cleartext, profileCipher, secret_key);
			byte[] email_ciphertext = Encryption.encrypt(email_cleartext, profileCipher, secret_key);
			
			//Store the encrypted customer profile information:
			CustomerProfile.setEncryptedName(name_ciphertext);
			CustomerProfile.setEncryptedAddress(address_ciphertext);
			CustomerProfile.setEncryptedPhoneNum(phone_num_ciphertext);
			CustomerProfile.setEncryptedEmail(email_ciphertext);
			
			//set Customer Profile Attributes to ciphertext:
			System.out.println("Encrypted Customer Profile: ");
			System.out.println("Name: "+name_ciphertext);
			System.out.println("Address: "+address_ciphertext);
			System.out.println("Phone Number: "+phone_num_ciphertext);
			System.out.println("Email: "+email_ciphertext);
			
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	//Decrypt the encrypted profile if the security code from phone is correct
	static void decryptProfile() {
		try {
			System.out.println("----- DECRYPTING PROFILE TO INTEGRATE CHANGES... -----");
			//Convert all of the profile information into byte arrays
			byte[] name_cleartext = Decryption.decrypt(encrypted_name, profileCipher, secret_key);
			byte[] address_cleartext = Decryption.decrypt(encrypted_address, profileCipher, secret_key);
			byte[] phone_num_cleartext = Decryption.decrypt(encrypted_phone_num, profileCipher, secret_key);
			byte[] email_cleartext = Decryption.decrypt(encrypted_email, profileCipher, secret_key);
		
			//set Customer Profile Attributes to ciphertext:
			CustomerProfile.setName(new String(name_cleartext));
			CustomerProfile.setAddress(new String(address_cleartext));
			CustomerProfile.setPhoneNum(new String(phone_num_cleartext));
			CustomerProfile.setEmail(new String(email_cleartext));
			
			//After decrypting the profile, hide the profile sensitive information and send the profile to the profile manager
			SensitiveProfileHider.hide_sensitive_profile();
		
		}
		catch(Exception e) {
			e.printStackTrace();
		}
		
	}
	
	//Request user input to change profile
	static void changeProfile() {
		Scanner keyboard = new Scanner(System.in); //Scanner to get user input
		//Ask for user input to change the profile and update the user information 
		System.out.println("\nPlease enter the new name: ");
		CustomerProfile.setName(keyboard.nextLine());
		System.out.println("\nPlease enter the new address: ");
		CustomerProfile.setAddress(keyboard.nextLine());
		System.out.println("\nPlease enter the new phone number: ");
		CustomerProfile.setPhoneNum(keyboard.nextLine());
		System.out.println("\nPlease enter the new email: ");
		CustomerProfile.setEmail(keyboard.nextLine());
		
		//After changing the profile information, send the confirmation to the profile manager
		ProfileManager.changeProfileConfirmation();
	}
	
	
	
	
}

class SensitiveProfileHider{
	
	static void hide_sensitive_profile() {
		System.out.println("----- Hiding Sensitive Profile Information... -----");
		//I am assuming that phone number, email, and address are sensitive information that needs to be hidden...
		System.out.println("Customer Profile: ");
		System.out.println("Name: "+CustomerProfile.getName());
		System.out.println("Address: (HIDDEN)");
		System.out.println("Phone Number: (HIDDEN)");
		System.out.println("Email: (HIDDEN)");
		
	}
}

//Application Cell phone class that receives the security code, decrypts it, then verifies that the security code is the same as the Customer's profile account security code
class CellPhone
{
	private static SecretKey secret_key; //The secret key used to decrypt the incoming security code
	
	//set methods for class attributes
	static void setSecKey (SecretKey input_sk) {
		secret_key = input_sk;
	}
	
	//get methods for class attributes
	static SecretKey getSecKey () {
		return secret_key;
	}
	
	
	//Receive method that receives the security code, decrypts it with the secret key, then prompts the user to enter in the security code to validate their identity
	static void receiveSecCode(byte[] ciphertext, Cipher aesCipher) {
		try {
			
			//Decrypt the encrypted security code with the .decrypt method from Encryption class
			byte[] cleartext = Decryption.decrypt(ciphertext, aesCipher, secret_key);
		
			String cleartextStr = new String(cleartext); //Converts the cleartext (byte array) to a regular string
			
			//Prompt the user to enter the security code
		
			System.out.println("\n\nDecrypted Security Code (Code on Customer's Phone):" +cleartextStr); //Test display after decrypting
			
			//Ask the user to provide the security code that was just decrypted by Cellphone and is showing:
			Scanner keyboard = new Scanner(System.in); //Scanner to get user input
			System.out.println("\nPlease enter in the security code (Enter the Decrypted security code above): ");
			String sec_code_input = keyboard.nextLine();
			
			
			System.out.println("----- CHECKING IF SECURITY CODE INPUT IS CORRECT -----");
			
			//If statement to check the correctness of entered security code to cellphone 
			if(sec_code_input.equals(CustomerProfile.getSecCode())) {
				AuthorizationCodeChecker.validOrNot(true); //Send that the code has been validated to the authorization code checker
				
				
			}
			else { //If the security code is NOT correct, print out error message and system terminates.
				AuthorizationCodeChecker.validOrNot(false); //Send that the code has been invalid to the authorization code checker
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
	}
}
 
//Application Class Customer Interface
class CustomerInterface{
	private static String security_code; //Security code generated
	
	//Set Security code to send to the authorization code checker
	static void setSecurityCode(int random_4dig_sec_code) {
		security_code = String.valueOf(random_4dig_sec_code);  //Assign security code value
	}
	
	//Request profile from profile manager
	static void requestProfile() {
		ProfileManager.requestProfile();
	}
	
	//Send Security code to the aurthorization code checker
	static void sendSecCode() {
		CustomerProfile.setSecCode(security_code); //Set the secCode
		AuthorizationCodeChecker.sendSecCode(security_code); //Send the security code to the authorization code checker
	}
	
	//Displays the customer's profile information
	static void displayCustomerProfile() {
		System.out.println("Customer Profile: ");
		System.out.println("Name: "+CustomerProfile.getName());
		System.out.println("Address: "+CustomerProfile.getAddress());
		System.out.println("Phone Number: "+CustomerProfile.getPhoneNum());
		System.out.println("Email: "+CustomerProfile.getEmail());
	}
	
	//Request a change to the customer's profile to the profile manager
	static void changeProfile() {
		ProfileManager.changeProfile();
	}
	
	//Displays a message for change profile confirmation
	static void changeProfileConfirmation() {
		System.out.println("----- Change Profile Has Been Confirmed. -----");
	}
	
}

//Application Class Customer Interface
class ProfileManager{
	
	//Requests the customer profile from Customer object
	static void requestProfile() {
		System.out.println("----- Requesting Customer Profile to display... -----");
	}
	
	//Get the customer profile
	static void displayCustomerProfile() {
		CustomerInterface.displayCustomerProfile();
	}
	
	//Request to change the profile
	static void changeProfile() {
		CustomerProfile.changeProfile();
	}
	
	//Sends confirmation to customer interface that profile has been changed
	static void changeProfileConfirmation() {
		CustomerInterface.changeProfileConfirmation();
	}
}

//Authorization Code Checker
class AuthorizationCodeChecker{
	
	//Send the security code to the customer device interface
	static void sendSecCode(String security_code) {
		customerDeviceInterface.sendSecCode(security_code, CustomerProfile.getSecKey()); //Send the security code and the secret key to the customer device interface
	}
	
	//Check to see if the code was valid or not from the Cell phone input. If it is, then tell the customer profile to decrypt itself:
	static void validOrNot(Boolean bool) {
		if (bool == true) { //if the authorization code checker is VALID, then authorize the customer profile decryption.
			System.out.println("----- SECURITY CODE INPUT IS CORRECT AND VALIDATED. PROCEEDING WITH CHANGE PROFILE REQUEST... -----");
			CustomerProfile.decryptProfile(); //Run the decrypt profile after validating that the cellphone security code is correct
		}
		else { //if the authorization is INVALID, then print out error message and system terminates.
			System.out.println("----- SECURITY CODE IS INCORRECT. TERMINATING SYSTEM... -----");
			System.exit(0); //exit system
		}
		
	}
}

//Customer Device Interface
class customerDeviceInterface{
	
	//Send the security code to the Cell phone object
	//Encrypts the security code and sends it to the cell phone object
		static void sendSecCode(String SecurityCode, SecretKey secret_key) {
			try {
				
				//Encrypt the security code
				byte[] cleartext = SecurityCode.getBytes(); //Converts the string security code into a byte array
				
				byte[] ciphertext = Encryption.encrypt(cleartext, CustomerProfile.getProfileCipher(), secret_key); //Encrypt the cleartext byte array to ciphertext by encrypting it with the cipher
				
				System.out.println("\nEncrypted security code :" +ciphertext); //Test display to show the encrypted security code
				
				//Call receive SecCode and send the ciphertext Security Code, and send the aesCipher to decrypt
				CellPhone.receiveSecCode(ciphertext, CustomerProfile.getProfileCipher());
				
			}
			catch(Exception e) {
				e.printStackTrace();
			}
		}
	
}

//key class for the secret key generation
class key{
	
	//Uses the aes to generate the secret_key for use in all the encryption and decryption stuff
	static void generate_secret_key() {
		try{
		//Generate a secret key first to be used for the cell phone decryption/security code encryption
		//Note: KeyPairGenerator is used for public and private key pair, KeyGenerator is just for 1 secret key
		//128 bits default size
		KeyGenerator keygen = KeyGenerator.getInstance("AES"); //make a secret key generator to make a secret key with
		SecretKey key = keygen.generateKey(); //Generates the secret key for encrypting and decrypting the security code for the cell phone class
		//Note: pass this key to the phone class to decrypt the encrypted security code
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); //Makes an AES cipher to encrypt and decrypt the secret key/security code
		
		
		//Pass the secret key to both the user profile and the cellphone for security code encryption and decryption
		CellPhone.setSecKey(key);
		CustomerProfile.setSecKey(key);
		CustomerProfile.setProfileCipher(aesCipher);
	}
		catch(Exception e) {
			e.printStackTrace();
		}
}
}

//Main method class
public class ChangeProfileTest {
	public static void main(String[] args) {
		//Implement the Secure Communication diagram application classes and the six security classes
			try {
			
			key.generate_secret_key(); //This generates all the secret key and cipher stuff for the code.
			
			//Starting User Profile information BEFORE the request to change the profile
			CustomerProfile.setName("John Arbuckle");
			CustomerProfile.setAddress("2214 Alisa Ln, 79407, Tx");
			CustomerProfile.setPhoneNum("806-324-7123");
			CustomerProfile.setEmail("JohnA2004@gmail.com");
			
			
			//Test display for the customer's profile
			System.out.println("Customer Profile BEFORE change profile request: ");
			CustomerInterface.displayCustomerProfile();
			
			
			//Test message that starts the change profile request 
			System.out.println("----- ENCRYPTING PROFILE BEFORE CHANGE PROFILE USE CASE -----");
			CustomerProfile.encryptProfile();
			
			//Request the profile from the profile manager
			CustomerInterface.requestProfile();
			
			
			
			System.out.println("----- GENERATING SECURITY CODE AND SENDING IT TO CELLPHONE OBJECT -----");
			//Generate the random 4 digit integer code and convert that to a string 
			int random_sec_code = (int)(Math.random()*(10000-1000))+ 1000; //Range is set between 1000 and 10000, where the 10000 is exclusive so it will always generate a 4 digit number
			//Set the security code and send to the Cell phone object
			CustomerInterface.setSecurityCode(random_sec_code);
			CustomerInterface.sendSecCode();
			
			//After verifying the security code to get into the account and drcrypt it, request change profile and get user input from customer interface:
			CustomerInterface.changeProfile();
			
			//After changing profile, confirm the changes by displaying out the new profile.
			CustomerInterface.displayCustomerProfile();
			
			//Then after changing the profile, encrypt the profile again
			System.out.println("----- Encrypting Profile Again -----");
			CustomerProfile.encryptProfile();
			
			
		 	}
			catch (Exception e){
		 		e.printStackTrace();
		 	}
	}

}

