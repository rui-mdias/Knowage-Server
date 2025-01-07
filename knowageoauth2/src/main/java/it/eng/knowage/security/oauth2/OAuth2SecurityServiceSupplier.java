/* SpagoBI, the Open Source Business Intelligence suite

 * Copyright (C) 2012 Engineering Ingegneria Informatica S.p.A. - SpagoBI Competency Center
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0, without the "Incompatible With Secondary Licenses" notice.
 * If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */
package it.eng.knowage.security.oauth2;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

//import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.Header;

import org.apache.log4j.LogMF;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import it.eng.spagobi.commons.SingletonConfig;
import it.eng.spagobi.services.security.bo.SpagoBIUserProfile;
import it.eng.spagobi.services.security.service.ISecurityServiceSupplier;
import it.eng.spagobi.utilities.exceptions.SpagoBIRuntimeException;

/**
 * @author Alessandro Daniele (alessandro.daniele@eng.it)
 * @author Jeremy Branham (jeremy@savantly.net)
 *
 */
public class OAuth2SecurityServiceSupplier implements ISecurityServiceSupplier {
	static private Logger logger = Logger.getLogger(OAuth2SecurityServiceSupplier.class);

	@Override
	public SpagoBIUserProfile createUserProfileOauth2(JSONObject jsonObjectInput) {
		logger.debug("IN");

		SpagoBIUserProfile profile;
		try {
			OAuth2Config config = OAuth2Config.getInstance();

			//OAuth2Client oauth2Client = new OAuth2Client();

			//HttpClient httpClient = oauth2Client.getHttpClient();
			// Inicialização do HttpClient e HttpGet
			HttpGet httpget = new HttpGet(config.getUserInfoUrl());
			CloseableHttpClient client = HttpClients.createDefault();

			// Inicialização do HttpClient e HttpGet

			// We call the OAuth2 provider to get user's info
			//GetMethod httpget = new GetMethod(config.getUserInfoUrl());
			
			logger.debug("REAL DEBUG 1:");

			
			// TODO: This will fail if the access token is expired, and the UX does not reflect the actual cause.
			// We should be using a refresh token I think.
			//httpget.addRequestHeader("Authorization", "Bearer " + userUniqueIdentifier);
			String userUniqueIdentifier = jsonObjectInput.getString("access_token");
			String refreshtoken = jsonObjectInput.getString("refresh_token");

			httpget.addHeader("Authorization", "Bearer " + userUniqueIdentifier);

			// debug - RAD
            // Debug: Inspeciona a requisição
            logger.debug("REAL DEBUG HTTP Method: " + httpget.getMethod());
            logger.debug("REAL DEBUG URL: " + httpget.getURI().toString());

            // Inspeciona os cabeçalhos da request
            Header[] headers = httpget.getAllHeaders();
            for (Header header : headers) {
                logger.debug("REAL DEBUG Header: " + header.getName() + " = " + header.getValue());
            }
			// debug - RAD
			    
			// Obter o código de status da resposta
			//int statusCode = httpClient.executeMethod(httpget);
			//byte[] response = httpget.getResponseBody();

			HttpResponse response = client.execute(httpget);
    
    		// Obter o código de status da resposta
    		int statusCode = response.getStatusLine().getStatusCode();

    		// Lê o corpo da resposta
    		String responseStr = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

			
			if (responseStr != null) {
    			logger.debug("REAL DEBUG 2: statusCode: " + statusCode + " response: " + responseStr + " userUniqueIdentifier: " + userUniqueIdentifier);
			} else {
    			logger.debug("REAL DEBUG 2: statusCode: " + statusCode + " response is null. userUniqueIdentifier: " + userUniqueIdentifier);
			}
			
			if (statusCode != HttpStatus.SC_OK) {
				logger.error("Error while getting user information from OAuth2 provider: server returned statusCode = "
						+ statusCode);
				LogMF.error(logger, "Server response is:\n{0}", new Object[] { responseStr });
				throw new SpagoBIRuntimeException(
						"Error while getting user information from OAuth2 provider: server returned statusCode = "
								+ statusCode);
			}

			//String responseStr = new String(response);
			LogMF.debug(logger, "Server response is:\n{0}", responseStr);
			JSONObject jsonObject = new JSONObject(responseStr);

			String userId = jsonObject.getString(config.getUserIdClaim());
			logger.debug("User id is [" + userId + "]");
			String userName = jsonObject.getString(config.getUserNameClaim());
			logger.debug("User name is [" + userName + "]");

			String clientid = config.getClientId();

			profile = new SpagoBIUserProfile();
			profile.setUniqueIdentifier(userUniqueIdentifier); // The OAuth2
																// access token
			profile.setRefreshToken(refreshtoken);
			profile.setClientId(clientid);

			profile.setUserId(userId);
			profile.setUserName(userName);
			profile.setOrganization("DEFAULT_TENANT");

			/*
			 * If the user's email is the same as the owner of the application (as
			 * configured in the oauth2.config.properties file) we consider him as the
			 * superadmin
			 */
			String adminEmail = config.getAdminEmail();
			String email = jsonObject.getString("email");
			profile.setIsSuperadmin(email.equalsIgnoreCase(adminEmail));

			//
			
			
			// Inicializar a lista de roles
			List<String> roles = new ArrayList<String>();

			// Verificar se os papéis estão em "resource_access.knowage-dev.roles"
			if (jsonObject.has("resource_access")) {
    			JSONObject resourceAccess = jsonObject.getJSONObject("resource_access");
    
    			if (resourceAccess.has(clientid)) {
        			JSONObject knowageRole = resourceAccess.getJSONObject(clientid);
        
        			if (knowageRole.has("roles")) {
            			JSONArray jsonRolesArray = knowageRole.getJSONArray("roles");
            
            			// Adicionar os papéis encontrados à lista
            			for (int i = 0; i < jsonRolesArray.length(); i++) {
                			String name = jsonRolesArray.getString(i);
                			if (Objects.nonNull(name)) {
                    			roles.add(name.toLowerCase());
                			}
            			}
        			}
    			}
			}
			//
			// Caso nenhum papel tenha sido encontrado em "knowage-dev", verificar diretamente em "roles"
			if (roles.isEmpty() && jsonObject.has("roles")) {
    			JSONArray jsonRolesArray = jsonObject.getJSONArray("roles");
    			for (int i = 0; i < jsonRolesArray.length(); i++) {
        			String name = jsonRolesArray.getString(i);
        			if (Objects.nonNull(name)) {
            			roles.add(name.toLowerCase());
        			}
    			}
			}
			//
			// If no roles were found, search for roles in the organizations
			if (roles.size() == 0 && !jsonObject.isNull("organizations")) {
				JSONArray organizations = jsonObject.getJSONArray("organizations");

				// TODO: something?
			}

			if (roles.size() == 0) { // Add the default role
				roles.add(SingletonConfig.getInstance().getConfigValue("SPAGOBI.SECURITY.DEFAULT_ROLE_ON_SIGNUP"));
			}

			String[] rolesString = new String[roles.size()];
			profile.setRoles(roles.toArray(rolesString));

			HashMap<String, String> attributes = new HashMap<String, String>();
			attributes.put("userUniqueIdentifier", userUniqueIdentifier);
			attributes.put("userId", userId);
			attributes.put("userName", userName);
			attributes.put("email", email);
			//
			attributes.put("clientid", clientid);
			attributes.put("refreshtoken", refreshtoken);
			
			// add any attributes configured by the env
			config.getProfileAttributes().forEach(a -> {
				attributes.put(a, jsonObject.optString(a));
			});
			
			profile.setAttributes(attributes);

			logger.debug("REAL DEBUG 3:" + "roles:" + roles + "profiles:" + profile);
			return profile;


		} catch (Exception e) {
			throw new SpagoBIRuntimeException(
					"Error while trying to read JSon object containing user profile's information from OAuth2 provider",
					e);
		} finally {
			logger.debug("REAL DEBUG 4 finally:");

			logger.debug("OUT");
		}
	}

//
@Override
public SpagoBIUserProfile createUserProfile(String userid) {
	logger.debug("IN");

	SpagoBIUserProfile profile;
	try {
		OAuth2Config config = OAuth2Config.getInstance();

		//OAuth2Client oauth2Client = new OAuth2Client();

		//HttpClient httpClient = oauth2Client.getHttpClient();
		// Inicialização do HttpClient e HttpGet
		HttpGet httpget = new HttpGet(config.getUserInfoUrl());
		CloseableHttpClient client = HttpClients.createDefault();

		// Inicialização do HttpClient e HttpGet

		// We call the OAuth2 provider to get user's info
		//GetMethod httpget = new GetMethod(config.getUserInfoUrl());
		
		logger.debug("REAL DEBUG 11:");

		
		// TODO: This will fail if the access token is expired, and the UX does not reflect the actual cause.
		// We should be using a refresh token I think.
		//httpget.addRequestHeader("Authorization", "Bearer " + userUniqueIdentifier);
		String userUniqueIdentifier = userid;
		logger.debug("ENTREI ONDE NAO QUERIA: " + userUniqueIdentifier);
		httpget.addHeader("Authorization", "Bearer " + userUniqueIdentifier);

		// debug - RAD
		// Debug: Inspeciona a requisição
		logger.debug("REAL DEBUG HTTP Method: " + httpget.getMethod());
		logger.debug("REAL DEBUG URL: " + httpget.getURI().toString());

		// Inspeciona os cabeçalhos da request
		Header[] headers = httpget.getAllHeaders();
		for (Header header : headers) {
			logger.debug("REAL DEBUG Header: " + header.getName() + " = " + header.getValue());
		}
		// debug - RAD
			
		// Obter o código de status da resposta
		//int statusCode = httpClient.executeMethod(httpget);
		//byte[] response = httpget.getResponseBody();

		HttpResponse response = client.execute(httpget);

		// Obter o código de status da resposta
		int statusCode = response.getStatusLine().getStatusCode();

		// Lê o corpo da resposta
		String responseStr = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

		
		if (responseStr != null) {
			logger.debug("REAL DEBUG 22: statusCode: " + statusCode + " response: " + responseStr + " userUniqueIdentifier: " + userUniqueIdentifier);
		} else {
			logger.debug("REAL DEBUG 22: statusCode: " + statusCode + " response is null. userUniqueIdentifier: " + userUniqueIdentifier);
		}
		
		if (statusCode != HttpStatus.SC_OK) {
			logger.error("Error while getting user information from OAuth2 provider: server returned statusCode = "
					+ statusCode);
			LogMF.error(logger, "Server response is:\n{0}", new Object[] { responseStr });
			throw new SpagoBIRuntimeException(
					"Error while getting user information from OAuth2 provider: server returned statusCode = "
							+ statusCode);
		}

		//String responseStr = new String(response);
		LogMF.debug(logger, "Server response is:\n{0}", responseStr);
		JSONObject jsonObject = new JSONObject(responseStr);

		String userId = jsonObject.getString(config.getUserIdClaim());
		logger.debug("User id is [" + userId + "]");
		String userName = jsonObject.getString(config.getUserNameClaim());
		logger.debug("User name is [" + userName + "]");

		profile = new SpagoBIUserProfile();
		profile.setUniqueIdentifier(userUniqueIdentifier); // The OAuth2
															// access token
		profile.setUserId(userId);
		profile.setUserName(userName);
		profile.setOrganization("DEFAULT_TENANT");

		/*
		 * If the user's email is the same as the owner of the application (as
		 * configured in the oauth2.config.properties file) we consider him as the
		 * superadmin
		 */
		String adminEmail = config.getAdminEmail();
		String email = jsonObject.getString("email");
		profile.setIsSuperadmin(email.equalsIgnoreCase(adminEmail));

		//
		String clientid = config.getClientId();
		
		// Inicializar a lista de roles
		List<String> roles = new ArrayList<String>();

		// Verificar se os papéis estão em "resource_access.knowage-dev.roles"
		if (jsonObject.has("resource_access")) {
			JSONObject resourceAccess = jsonObject.getJSONObject("resource_access");

			if (resourceAccess.has(clientid)) {
				JSONObject knowageRole = resourceAccess.getJSONObject(clientid);
	
				if (knowageRole.has("roles")) {
					JSONArray jsonRolesArray = knowageRole.getJSONArray("roles");
		
					// Adicionar os papéis encontrados à lista
					for (int i = 0; i < jsonRolesArray.length(); i++) {
						String name = jsonRolesArray.getString(i);
						if (Objects.nonNull(name)) {
							roles.add(name.toLowerCase());
						}
					}
				}
			}
		}
		//
		// Caso nenhum papel tenha sido encontrado em "knowage-dev", verificar diretamente em "roles"
		if (roles.isEmpty() && jsonObject.has("roles")) {
			JSONArray jsonRolesArray = jsonObject.getJSONArray("roles");
			for (int i = 0; i < jsonRolesArray.length(); i++) {
				String name = jsonRolesArray.getString(i);
				if (Objects.nonNull(name)) {
					roles.add(name.toLowerCase());
				}
			}
		}
		//
		// If no roles were found, search for roles in the organizations
		if (roles.size() == 0 && !jsonObject.isNull("organizations")) {
			JSONArray organizations = jsonObject.getJSONArray("organizations");

			// TODO: something?
		}

		if (roles.size() == 0) { // Add the default role
			roles.add(SingletonConfig.getInstance().getConfigValue("SPAGOBI.SECURITY.DEFAULT_ROLE_ON_SIGNUP"));
		}

		String[] rolesString = new String[roles.size()];
		profile.setRoles(roles.toArray(rolesString));

		HashMap<String, String> attributes = new HashMap<String, String>();
		attributes.put("userUniqueIdentifier", userUniqueIdentifier);
		attributes.put("userId", userId);
		attributes.put("userName", userName);
		attributes.put("email", email);

		
		// add any attributes configured by the env
		config.getProfileAttributes().forEach(a -> {
			attributes.put(a, jsonObject.optString(a));
		});
		
		profile.setAttributes(attributes);

		logger.debug("REAL DEBUG 32:" + "roles:" + roles + "profiles:" + profile);
		return profile;


	} catch (Exception e) {
		throw new SpagoBIRuntimeException(
				"Error while trying to read JSon object containing user profile's information from OAuth2 provider",
				e);
	} finally {
		logger.debug("REAL DEBUG 4 finally:");

		logger.debug("OUT");
	}
}


	@Override
	public SpagoBIUserProfile checkAuthentication(String userId, String psw) {
		OAuth2Client oauth2Client = new OAuth2Client();
		return createUserProfile(oauth2Client.getAccessTokenWithPassword(userId, psw));
	}

	@Override
	public SpagoBIUserProfile checkAuthenticationWithOauth2(String userId, String psw) {
		OAuth2Client oauth2Client = new OAuth2Client();
		//String accessToken = oauth2Client.getAccessTokenWithPassword(userId, psw);
		return createUserProfileOauth2(oauth2Client.getAccessOAuth2TokenWithPassword(userId, psw));
	}
	
	@Override
	public SpagoBIUserProfile checkAuthenticationWithToken(String userId, String token) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean checkAuthorization(String userId, String function) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public SpagoBIUserProfile checkAuthenticationToken(String token) {
		return createUserProfile(token);
	}



}
