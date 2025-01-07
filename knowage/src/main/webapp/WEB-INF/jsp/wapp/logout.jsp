<%-- 
Knowage, Open Source Business Intelligence suite 
Copyright (C) 2016 Engineering Ingegneria Informatica S.p.A.

Knowage is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Knowage is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see http://www.gnu.org/licenses/.
--%>

<%@page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@page import="java.util.HashMap"%>
<%@page import="java.net.URLEncoder" %>
<%@page import="java.nio.charset.StandardCharsets" %>
<%@page import="it.eng.spago.security.IEngUserProfile"%>    
<%@page import="it.eng.spagobi.commons.SingletonConfig"%>
<%@page import="it.eng.spagobi.commons.utilities.AuditLogUtilities"%>
<%@page import="it.eng.spagobi.commons.constants.SpagoBIConstants"%>
<%@page import="it.eng.spagobi.commons.constants.CommunityFunctionalityConstants"%>
<%@page import="it.eng.spagobi.commons.utilities.GeneralUtilities"%>
<%@page import="it.eng.knowage.commons.security.KnowageSystemConfiguration"%>
<%@page import="it.eng.spagobi.security.google.config.GoogleSignInConfig"%>
<%@page import="it.eng.spago.base.SessionContainer"%>
<%@page import="it.eng.spago.base.RequestContainer"%>
<%@page import="it.eng.knowage.security.oauth2.OAuth2Config" %>


<%
boolean backUrlB = false;
String backUrl = "";
String redirectUrl = "";

if (session.getAttribute(SpagoBIConstants.BACK_URL) != null) {
    backUrl = (String) session.getAttribute(SpagoBIConstants.BACK_URL);
    backUrlB = true;
}


RequestContainer reqCont = RequestContainer.getRequestContainer();
SessionContainer sessCont = reqCont.getSessionContainer();
SessionContainer permSess = sessCont.getPermanentContainer();


IEngUserProfile profile = (IEngUserProfile) permSess.getAttribute(IEngUserProfile.ENG_USER_PROFILE);

// OAuth2Config oAuth2Config = OAuth2Config.getInstance();

String contextt = request.getContextPath();

String backUrll = null;
String userUniqueIdentifier = null;
String refresh_token = null;
String client_id = null;


String redirectAddress = OAuth2Config.getInstance().getRedirectUrl();

if (profile != null) {
	userUniqueIdentifier = (String) profile.getUserAttribute("userUniqueIdentifier");
    refresh_token = (String) profile.getUserAttribute("refreshtoken");
	client_id = (String) profile.getUserAttribute("clientid");    
 }

%>


<script>	
    // Exibe o identificador único do utilizador ou indica que não foi encontrado
	const contextt = "<%= contextt != null ? contextt : "null" %>";

    const userUniqueIdentifier = "<%= userUniqueIdentifier != null ? userUniqueIdentifier : "null" %>";
    const refresh_token = "<%= refresh_token != null ? refresh_token : "null" %>";

    const client_id = "<%= client_id != null ? client_id : "null" %>";

    const permSess = "<%= permSess != null ? permSess : "null" %>";
    
    const backUrll = "<%= backUrl != null ? backUrl : "null" %>";
    const profile =  "<%= profile != null ? profile : "null" %>";

//	if (profile !== "null") {
//        alert("client_id_atributo: " + client_id + " refresh_token_atributo:" + refresh_token + 
//		" context:" + contextt + " backUrll:" + backUrll);
//    } else {
//        alert("profile NULL.");
//    }
</script>

<%
if (profile != null) {
    // Removing user profile object from permanent container
    permSess.setAttribute(IEngUserProfile.ENG_USER_PROFILE, null);
    HashMap<String, String> logParam = new HashMap<String, String>();
    logParam.put("USER", profile.toString());
    AuditLogUtilities.updateAudit(request, profile, "SPAGOBI.Logout", logParam, "OK");
}

// Invalidate HTTP session
session.invalidate();

// Check if SSO is active
String active = SingletonConfig.getInstance().getConfigValue("SPAGOBI_SSO.ACTIVE");
String strUsePublicUser = SingletonConfig.getInstance().getConfigValue(SpagoBIConstants.USE_PUBLIC_USER);
Boolean usePublicUser = (strUsePublicUser == null) ? false : Boolean.valueOf(strUsePublicUser);


if ((active == null || active.equalsIgnoreCase("false")) && !backUrlB) {
    String context = request.getContextPath();
    if (usePublicUser) {
        context += "/servlet/AdapterHTTP?PAGE=LoginPage&NEW_SESSION=TRUE";
        redirectUrl = context;
    } else {
        redirectUrl = context;
    }
//
} else if (active != null && active.equalsIgnoreCase("true")) {
    String urlLogout = SingletonConfig.getInstance().getConfigValue("SPAGOBI_SSO.SECURITY_LOGOUT_URL");

    if (urlLogout != null) {
        String redirectUri = redirectAddress;
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8.toString());
       // redirectUri="https://knowage-dev.apps.ocp4.ptinfra.com/knowage/servlet/AdapterHTTP?PAGE=LoginPage&NEW_SESSION=TRUE";
        // Define o redirect URL com um marcador que será resolvido no cliente
        // redirectUrl = urlLogout
        redirectUrl = null;
        redirectUrl = urlLogout
            + "?client_id=${p_client_id}"
            + "&post_logout_redirect_uri=" + encodedRedirectUri
            + "&refresh_token=${refresh_id_token}";
    } else {
        redirectUrl = request.getContextPath() + "/servlet/AdapterHTTP?PAGE=LoginPage&NEW_SESSION=TRUE";
    }
} else if (backUrlB) {
    redirectUrl = backUrl;
}

%>

<script>
function invalidateNoError(url) {
    return new Promise(function(resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open("GET", url, true);
        xhr.onload = function() {
            resolve(true);
        };
        xhr.onerror = function() {
            resolve(true);
        };
        xhr.send();
    });
}


///
function redirect() {
	var redirectUrl = "<%= redirectUrl %>";
	redirectUrl = resolveDynamicParameters(redirectUrl);
	window.sessionStorage.removeItem("id_token");
	window.location = redirectUrl;
};

function resolveDynamicParameters(url) {
	///
	//const idToken = window.sessionStorage.getItem("id_token");
    //const clientid = window.sessionStorage.getItem("client_id");
	const refreshtoken = refresh_token;
    const idToken = userUniqueIdentifier;
	//const idToken = refresh_token;
    const clientid = client_id;



//	console.debug("REAL DEBUG X: " + idToken);
	if (refreshtoken) {
        url = url.replace("<%= "${refresh_id_token}" %>", encodeURIComponent(refreshtoken));
    } 
    if (clientid) {
        url = url.replace("<%= "${p_client_id}" %>", encodeURIComponent(clientid));
    }
    if (idToken) {
        url = url.replace("<%= "${id_token}" %>", encodeURIComponent(idToken));
    }
//        console.warn("id_token não encontrado no sessionStorage.");
    return url; // Retorna a URL sem alteração    
	///
}

function setTimeoutToRedirect() {
	setTimeout(function(){
		redirect()
	}, 1000);
};

function invalidateAll() {
	Promise.all([
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageBirtReportEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageCockpitEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageCommonjEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageDossierEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageGeoReportEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageJasperReportEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageKpiEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageMetaContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageQbeEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageSvgViewerEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageTalendEngineContext()%>/invalidateSession.jsp"),
		invalidateNoError("<%=KnowageSystemConfiguration.getKnowageWhatifEngineContext()%>/invalidateSession.jsp")
	]).then(() => { redirect(); })
}
</script>


<% if (GoogleSignInConfig.isEnabled()) { %>

<%-- Resources for Google Sign-In authentication --%>
<script src="https://apis.google.com/js/platform.js?onload=onLoad" async defer></script>
<meta name="google-signin-client_id" content="<%= GoogleSignInConfig.getClientId() %>">
<script>
	function googleSignOut(callback, fail) {
		var auth2 = gapi.auth2.getAuthInstance();
		auth2.signOut().then(function() {
				auth2.disconnect();
				callback();
			}, 
			fail
		);
	};

	function onLoad() {
		gapi.load('auth2', function() {
			gapi.auth2.init().then(function () {
			
				googleSignOut(setTimeoutToRedirect, function () {
					alert("An error occurred during Google logout");
				});
			
			});
		});
	};

</script>
	
<% } else { %>

<script>
	invalidateAll();
</script>
	
<% } %>