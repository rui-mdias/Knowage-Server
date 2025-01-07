/*
 * Knowage, Open Source Business Intelligence suite
 * Copyright (C) 2016 Engineering Ingegneria Informatica S.p.A.
 *
 * Knowage is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Knowage is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package it.eng.spagobi.services.security.service;

import org.json.JSONObject;

import it.eng.spagobi.services.security.bo.SpagoBIUserProfile;

/**
 * The interface for the User Profile Factory, in order to manage user
 * information.
 */
public interface ISecurityServiceSupplier {

	/**
	 * 
	 * @return SpagoBIUserProfile
	 */

	/**
 	* Authenticates a user using OAuth2 and retrieves their profile.
 	* 
 	* @param userId   the unique identifier of the user
 	* @param password the user's password
 	* @return the SpagoBIUserProfile if authentication succeeds, or null if it fails
 	*/
	SpagoBIUserProfile checkAuthenticationWithOauth2(String userId, String password);	 
	/** 
	* Creates a user profile based on the user ID.
	* 
	* @param jsonInput the unique identifier of the user
	* @return the SpagoBIUserProfile, or null if the user is not found
	*/
	SpagoBIUserProfile createUserProfileOauth2(JSONObject jsonInput);
    /**
     * Creates a user profile based on the user ID.
     * 
     * @param userId the unique identifier of the user
	 * @param psw
	 * @return the SpagoBIUserProfile, or null if the user is not found
     */
	SpagoBIUserProfile createUserProfile(String userId);
	/**
	 * if SpagoBIUserProfile is NULL the password is incorrect!!!!
	 * 
	 * @param userId
	 * @param psw
	 * @return
	 */
	SpagoBIUserProfile checkAuthentication(String userId, String psw);

	SpagoBIUserProfile checkAuthenticationToken(String token);

	/**
	 * if SpagoBIUserProfile is NULL the token is incorrect!!!!
	 * 
	 * @param userId
	 * @param token
	 * @return
	 * 
	 * @deprecated
	 */
	@Deprecated
	SpagoBIUserProfile checkAuthenticationWithToken(String userId, String token);

	/**
	 * 
	 * @param userId
	 * @param function
	 * @return
	 * 
	 * @deprecated
	 */
	@Deprecated
	boolean checkAuthorization(String userId, String function);



}