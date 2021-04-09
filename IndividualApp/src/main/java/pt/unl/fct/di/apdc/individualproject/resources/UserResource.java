package pt.unl.fct.di.apdc.individualproject.resources;

import java.text.SimpleDateFormat;
import java.util.Date;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.cloud.datastore.*;
import com.google.gson.Gson;

import pt.unl.fct.di.apdc.individualproject.util.UserData;

@Path("/user")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class UserResource {

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private final Gson g = new Gson();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	private KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
	
	@POST
	@Path("/register")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response registUser(UserData data) {
		if(data.username == null || data.password == null || data.confirmation == null || data.email == null) {
			return Response.status(Response.Status.BAD_REQUEST).entity("Null data present, please fill all the information necessary.").build();
		}
		
		Transaction txn = datastore.newTransaction();
		Key userKey = userKeyFactory.newKey(data.username);
		Key profileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		
		try {
			Entity user = txn.get(userKey);
			Entity profile = txn.get(profileKey);
			
			if(!data.password.equals(data.confirmation)) {
				txn.rollback();
				return Response.status(Response.Status.CONFLICT).entity("Passwords do not match.").build();
			}
			
			if(data.password.length() < 6) {
				txn.rollback();
				return Response.status(Response.Status.CONFLICT).entity("Passwords must be longer than 6 characters.").build();
			}
			
			if(user != null) {
				txn.rollback();
				return Response.status(Response.Status.BAD_REQUEST).entity("Username " + data.username + " already exists.").build();
			}
			
			SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
			String timestamp  = dateFormat.format(new Date());
			
			user = Entity.newBuilder(userKey)
					.set("password", DigestUtils.sha512Hex(data.password))
					.set("email", data.email)
					.set("creation_timestamp", timestamp)
					.build();
			
			txn.add(user);
			
			profile = Entity.newBuilder(profileKey)
					.set("profile", "PRIVATE")
					.set("role", "U")
					.set("state", "ENABLED")
					.set("landline", "")
					.set("mobilePhone", "")
					.set("address", "")
					.set("complementAddress", "")
					.set("locality", "")
					.build();		
			
			txn.add(profile);
			txn.commit();
			return Response.ok().entity("New user registered with username " + data.username).build();
			
		} catch( Exception e ) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
		
	}
	
	
	@DELETE
	@Path("/delete")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response deleteUser(UserData data) {
		Transaction txn = datastore.newTransaction();
		Key userToRmKey = userKeyFactory.newKey(data.username);
		Key profileToRmKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key tokenToRmKey = tokenKeyFactory.newKey(data.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		try {
			Entity userToRm = txn.get(userToRmKey);
			Entity tokenToRm = txn.get(tokenToRmKey);
			Entity token = txn.get(tokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
				
				if(userToRm == null) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
				}
				
				String role = token.getString("role");
				if(data.username.equals(data.at.username) && role.equals("U")) {
					txn.delete(userToRmKey);
					txn.delete(profileToRmKey);
					if(tokenToRm != null)
						txn.delete(tokenToRmKey);
					txn.commit();
					return Response.ok().entity("User with username " + data.username + " removed.").build();
				} else if(!data.username.equals(data.at.username) && (role.equals("GBO") || role.equals("GA") || role.equals("SU"))){
					txn.delete(userToRmKey);
					txn.delete(profileToRmKey);
					if(tokenToRm != null)
						txn.delete(tokenToRmKey);
					txn.commit();
					return Response.ok().entity("User with username " + data.username + " removed.").build();
				} else {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity(data.at.username + " doesn't have permisson to remove this user").build();
				}
					
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
			
			
		} catch( Exception e ) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
		
	}
	
	@POST
	@Path("/modify")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyUserInfo(UserData data) {
		Transaction txn = datastore.newTransaction();
		Key userKey = userKeyFactory.newKey(data.at.username);
		Key oldProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.at.username))
				.setKind("Profile").newKey(data.at.username);
		Key newProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.at.username))
				.setKind("Profile").newKey(data.at.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		
		try {
			Entity user = txn.get(userKey);
			Entity profile = txn.get(oldProfileKey);
			Entity token = txn.get(tokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
			
				if(user == null) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
				}
				
				
				Entity newProfile = Entity.newBuilder(newProfileKey)
						.set("profile", (data.profile != null) ? data.profile : profile.getString("profile"))
						.set("role", profile.getString("role"))
						.set("state", profile.getString("state"))
						.set("landline", (data.landline != null) ? data.landline : profile.getString("landline"))
						.set("mobilePhone", (data.mobilePhone != null) ? data.mobilePhone : profile.getString("mobilePhone"))
						.set("address", (data.address != null) ? data.address : profile.getString("address"))
						.set("complementAddress", (data.complementAddress != null) ? data.complementAddress : profile.getString("complementAddress"))
						.set("locality", (data.locality != null) ? data.locality : profile.getString("locality"))
						.build();		
				
				txn.delete(oldProfileKey);
				txn.add(newProfile);
				txn.commit();
				
				return Response.ok().entity( data.at.username + " info updated.").build();
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
		} catch( Exception e ) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@POST
	@Path("/role")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyUserRole(UserData data) {
		Transaction txn = datastore.newTransaction();
		Key userKey = userKeyFactory.newKey(data.username);
		Key oldProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key newProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		Key oldTokenKey = tokenKeyFactory.newKey(data.username);
		Key newTokenKey = tokenKeyFactory.newKey(data.username);
		
		try {
			Entity user = txn.get(userKey);
			Entity profile = txn.get(oldProfileKey);
			Entity token = txn.get(tokenKey);
			Entity oldToken = txn.get(oldTokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
				if(user == null) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
				}
				
				String role = token.getString("role");
				if( profile.getString("role").equals("U") && ( (data.role.equals("GBO") && (role.equals("GA") || role.equals("SU")))
						|| (data.role.equals("GA") && role.equals("SU"))) ) {
					Entity newProfile = Entity.newBuilder(newProfileKey)
							.set("profile",  profile.getString("profile"))
							.set("role", data.role)
							.set("state", profile.getString("state"))
							.set("landline", profile.getString("landline"))
							.set("mobilePhone", profile.getString("mobilePhone"))
							.set("address", profile.getString("address"))
							.set("complementAddress", profile.getString("complementAddress"))
							.set("locality", profile.getString("locality"))
							.build();		
					
					txn.delete(oldProfileKey);
					txn.add(newProfile);
					if(oldToken != null) {
						Entity newToken = Entity.newBuilder(newTokenKey)
								.set("username", oldToken.getString("username"))
								.set("id", oldToken.getString("id"))
								.set("role", data.role)
								.set("creationData",oldToken.getLong("creationData"))
								.set("expirationData", oldToken.getLong("expirationData"))
								.build();
						txn.delete(oldTokenKey);
						txn.add(newToken);
					}
					txn.commit();
					
					return Response.ok().entity( data.username + " role updated to role " + data.role + ".").build();
				} else {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("No permisson to change role.").build();
				}
				
				
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
		} catch( Exception e ) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@POST
	@Path("/state")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyUserState(UserData data) {
		Transaction txn = datastore.newTransaction();
		Key userKey = userKeyFactory.newKey(data.username);
		Key oldProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key newProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		
		try {
			Entity user = txn.get(userKey);
			Entity profile = txn.get(oldProfileKey);
			Entity token = txn.get(tokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
			
			if(user == null) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
			}
			
			
				if(data.validStateChange(data.at.role, profile.getString("role"))) {
					Entity newProfile = Entity.newBuilder(newProfileKey)
							.set("profile",  profile.getString("profile"))
							.set("role", profile.getString("role"))
							.set("state", data.state)
							.set("landline", profile.getString("landline"))
							.set("mobilePhone", profile.getString("mobilePhone"))
							.set("address", profile.getString("address"))
							.set("complementAddress", profile.getString("complementAddress"))
							.set("locality", profile.getString("locality"))
							.build();		
					
					txn.delete(oldProfileKey);
					txn.add(newProfile);
					txn.commit();
					
					return Response.ok().entity( data.username + " state updated.").build();
				} else {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity(data.at.username + " not permited to change state of " + data.username).build();
				}
				
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
			
			
		} catch( Exception e ) {
	        txn.rollback();
	        return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@POST
	@Path("/newPassword")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response modifyUserPassword(UserData data) {
		Transaction txn = datastore.newTransaction();
		Key oldUserKey = userKeyFactory.newKey(data.at.username);
		Key newUserKey = userKeyFactory.newKey(data.at.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		
		try {
			
			Entity user = txn.get(oldUserKey);
			Entity token = txn.get(tokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
			
				if(data.oldPassword == null || data.password == null || data.confirmation == null ) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("Null password(s).").build();
				}
				
				if(!DigestUtils.sha512Hex(data.oldPassword).equals(user.getString("password"))) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("Old password incorrect.").build();
				}
				
				if(data.password.length() < 6) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("Passwords must be longer than 6 characters").build();
				}
				
				if(!data.password.equals(data.confirmation)) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("New password doesn't match with confirmation password.").build();
				}
				
				
				Entity newUser = Entity.newBuilder(newUserKey)
						.set("password", DigestUtils.sha512Hex(data.password))
						.set("email", user.getString("email"))
						.set("creation_timestamp", user.getString("creation_timestamp"))
						.build();
				
				txn.delete(oldUserKey);
				txn.add(newUser);
				txn.commit();
				
				return Response.ok().entity( data.at.username + " password updated.").build();
				
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
			
			
		} catch( Exception e ) {
	        txn.rollback();
	        return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@POST
	@Path("/attribute")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response getUserAttribute(UserData data) {
		Key userKey = userKeyFactory.newKey(data.username);
		Key profileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username); 
		Transaction txn = datastore.newTransaction();
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		
		try {
			
			Entity user = txn.get(userKey);
			Entity profile = txn.get(profileKey);
			Entity token = txn.get(tokenKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
				
				if(user == null) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
				}
				
				String role = token.getString("role");
				if(!role.equals("GBO") && !role.equals("GA") && !role.equals("SU")) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User not allowed to do this operation.").build();
				}
				
				return Response.ok(g.toJson(user) + "\n" + g.toJson(profile)).build();
				
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}
			
		} catch( Exception e ) {
	        txn.rollback();
	        return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@DELETE
	@Path("/disable")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response disableUser(UserData data) {
		Key userKey = userKeyFactory.newKey(data.username);
		Key oldProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key newProfileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		Key tokenToRmKey = tokenKeyFactory.newKey(data.username);
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity user = txn.get(userKey);
			Entity profile = txn.get(oldProfileKey);
			Entity token = txn.get(tokenKey);
			Entity tokenToRm = txn.get(tokenToRmKey);
			
			if(token != null && data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
				
				if(user == null) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
				}
				
				if(!data.at.role.equals("GA") && !data.at.role.equals("SU")){
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User not allowed to do this operation").build();
				}
	
				if(profile.getString("state").equals("ENABLED")) {
					Entity newProfile = Entity.newBuilder(newProfileKey)
							.set("profile",  profile.getString("profile"))
							.set("role", profile.getString("role"))
							.set("state", "DISABLED")
							.set("landline", profile.getString("landline"))
							.set("mobilePhone", profile.getString("mobilePhone"))
							.set("address", profile.getString("address"))
							.set("complementAddress", profile.getString("complementAddress"))
							.set("locality", profile.getString("locality"))
							.build();		
					
					txn.delete(oldProfileKey);
					if(tokenToRm != null)
						txn.delete(tokenToRmKey);
					txn.add(newProfile);
					txn.commit();
					
					return Response.ok().entity( data.username + " disabled.").build();
					
				} else {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User " + data.username + " already disabled.").build();
				}
				
			} else {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User not logged.").build();
			}	
			
		} catch( Exception e ) {
	        txn.rollback();
	        return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
}
