package pt.unl.fct.di.apdc.individualproject.resources;

import java.util.logging.Logger;

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

import pt.unl.fct.di.apdc.individualproject.util.AuthToken;
import pt.unl.fct.di.apdc.individualproject.util.LoginData;

@Path("/sign")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {
	/**
	 * A Logger Object
	 */
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private final Gson g = new Gson();
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");
	private KeyFactory tokenKeyFactory = datastore.newKeyFactory().setKind("Token");
	
	public LoginResource() {}
	
	@Path("/in")
	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response login(LoginData data) {
		LOG.fine("Login attempt by user: " + data.username);
		
		Key userKey = userKeyFactory.newKey(data.username);
		Key tokenKey = tokenKeyFactory.newKey(data.username);
		Key profileKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("Profile").newKey(data.username);
		Transaction txn = datastore.newTransaction();
		
		try {
		Entity user = txn.get(userKey);
		Entity profile = txn.get(profileKey);
		Entity oldToken = txn.get(tokenKey);
		
		if(oldToken != null) {
			txn.rollback();
			return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " already logged in.").build();
		}
		
		if(user == null) {
			txn.rollback();
			return Response.status(Status.FORBIDDEN).entity("User with username " + data.username + " does not exist.").build();
		}
		
		String hashedPWD = user.getString("password");
		if(!hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
			txn.rollback();
			return Response.status(Status.FORBIDDEN).entity("Incorret password.").build();
		}
		
		if(profile.getString("state").equals("DISABLED")) {
			txn.rollback();
			return Response.status(Status.FORBIDDEN).entity("Account disabled.").build();
		}
		
		AuthToken at = new AuthToken(data.username, profile.getString("role"));
		
		Entity token = Entity.newBuilder(tokenKey)
				.set("username", at.username)
				.set("id", at.tokenID)
				.set("role", at.role)
				.set("creationData", at.creationData)
				.set("expirationData", at.expirationData)
				.build();
		
		txn.put(token);
		txn.commit();
		
		return Response.ok(g.toJson(at)).build();
		} catch( Exception e ) {
            txn.rollback();
            return Response.status(Status.INTERNAL_SERVER_ERROR).entity("Something broke.").build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
			
	}
	
	@Path("/out")
	@DELETE
	public Response logout(LoginData data) {
		Key tokenKey = tokenKeyFactory.newKey(data.at.username);
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity token = txn.get(tokenKey);
			
			if(data.at.isValid(token.getLong("expirationData")) && data.at.tokenID.equals(token.getString("id"))) {
				txn.delete(tokenKey);
				txn.commit();
				return Response.ok().entity("User " + data.at.username + " logged out successfully.").build();
				
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
