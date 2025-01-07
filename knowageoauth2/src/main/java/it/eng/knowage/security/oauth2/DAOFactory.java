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
package it.eng.knowage.security.oauth2;

import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import it.eng.spago.error.EMFUserError;
import it.eng.spagobi.commons.SingletonConfig;
import it.eng.spagobi.utilities.exceptions.SpagoBIRuntimeException;

/**
 * Contains all the data access object for all the BO objects defined into it.eng.spagobi.bo package.
 */
public class DAOFactory {

	private static final String CONFIG_EMIT_AUTHORIZATION_EVENTS = "KNOWAGE.EMIT_AUTHORIZATION_EVENTS";
	private static final String KNOWAGE_EMIT_AUTHORIZATION_EVENTS_IMPL = "kn.emit.authorization.event.impl";

	private static final Logger LOGGER = LogManager.getLogger(DAOFactory.class);
	private static DAOFactory instance = null;
	
	private static String getDAOClass(String daoName) {
		return DAOConfig.getMappings().get(daoName);
	}

	/**
	 * Given, for a defined BO, its DAO name, creates the correct DAO instance
	 *
	 *
	 * @param daoName The BO DAO name
	 * @return An object representing the DAO instance
	 */

	private static Object createDAOInstance(String daoName) {
		Object daoObject = null;
		try {
			daoObject = Class.forName(getDAOClass(daoName)).newInstance();
		} catch (Throwable e) {
			throw new SpagoBIRuntimeException("Cannot instantiate " + daoName, e);
		}
		return daoObject;
	}


	public static ITenantsDAO getTenantsDAO() {
		return (ITenantsDAO) createDAOInstance("TenantsDAO");
	}


	private DAOFactory() {
	}

// Novas implementaçõrs

	public static DAOFactory getInstance() {
		if (instance == null) {
			instance = new DAOFactory();
		}
		return instance;
	}

}
