package com.wso2.identity.oauth.grant.fido;

import com.wso2.identity.api.fido2.common.exception.Fido2AuthenticatorServerException;
import com.wso2.identity.api.fido2.core.AuthenticationService;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.application.common.model.User;

import javax.ws.rs.core.Response;

import static com.wso2.identity.oauth.grant.fido.FIDOGrantConstants.*;

/**
 * New grant type for Identity Server
 */
public class FIDOGrantHandler extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(FIDOGrantHandler.class);


    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("FIDO Grant handler is hit");

        boolean authStatus;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String username = null;
        String response = null;

        // extract parameters
        for(RequestParameter parameter : parameters){
            if(GRANT_PARAM_RESPONSE_OBJECT.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    response = parameter.getValue()[0];
                }
            } else if(GRANT_PARAM_USERNAME.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    username = parameter.getValue()[0];
                }
            }
        }

        // Sanitize inputs.
        if (StringUtils.isBlank(username) || StringUtils.isBlank(response)) {
            String missingParam = StringUtils.isBlank(username) ? "username" : "response";
            throw new IdentityOAuth2Exception("Param is missing: " + missingParam);
        }

        // Retrieve user by username
        User user = User.getUserFromUserName(username);
        String tenantDomain = user.getTenantDomain();
        String userStoreDomain = user.getUserStoreDomain();

        //validate response
        authStatus =  isValidResponse(username, tenantDomain, userStoreDomain, response);

        if(authStatus) {

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(user.getUserName());
            authenticatedUser.setTenantDomain(user.getTenantDomain());
            authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUserName());
            authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());

            oAuthTokenReqMessageContext.setAuthorizedUser(authenticatedUser);
            oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
        } else{
            ResponseHeader responseHeader = new ResponseHeader();
            responseHeader.setKey("SampleHeader-999");
            responseHeader.setValue("Grant Invocation Failed.");
            oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
        }

        return authStatus;
    }

    private boolean isValidResponse(String username, String tenantDomain, String userStoreDomain, String response) throws IdentityOAuth2Exception {

        try {
            AuthenticationService authService = new AuthenticationService();
            authService.finishAuthentication(username, tenantDomain,
                    userStoreDomain, response);

            return true;

        } catch (Fido2AuthenticatorServerException e) {
            throw new IdentityOAuth2Exception(e.getErrorCode(), e.getDescription(), e);
        }

    }
    
}
