package pt.unl.fct.di.apdc.individualproject.util;

public class LoginData {
	
	public String username;
	public String password;
	
	public AuthToken at;
	
	public LoginData() {}
	
	public LoginData(String username, String password) {
		this.username = username;
		this.password = password;
	}

}
