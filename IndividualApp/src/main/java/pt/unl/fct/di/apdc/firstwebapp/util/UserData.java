package pt.unl.fct.di.apdc.firstwebapp.util;

public class UserData {
	
	//ROLES
	public static final String USER = "U";
	public static final String BACKOFFICE = "GBO";
	public static final String BACKEND = "GA";
	public static final String SUPER = "SU";
	
	//STATE
	public static final String ENABLED = "ENABLED";
	public static final String DISABLED = "DISABLED";
	
	//PROFILE
	public static final String PUBLIC = "PUBLIC";
	public static final String PRIVATE = "PRIVATE";
	
	public String username;
	public String password;
	public String confirmation;
	public String email;
	
	public String role;
	public String state;
	public String profile;
	public String landline;
	public String mobilePhone;
	public String address;
	public String complementAddress;
	public String locality;
	
	public String oldPassword;
	
	public AuthToken at;
	
	public UserData() {}
	
	
	public boolean validStateChange(String changer, String toChange) {
		if(changer.equals(USER))
			return false;
		
		if(toChange.equals(USER) && (changer.equals(BACKOFFICE) || changer.equals(BACKEND) || changer.equals(SUPER)))
			return true;
		
		if(toChange.equals(BACKOFFICE) && (changer.equals(BACKEND) || changer.equals(SUPER)))
			return true;
		
		if(toChange.equals(BACKEND) && (changer.equals(SUPER)))
			return true;
		
		return false;
	}

}
