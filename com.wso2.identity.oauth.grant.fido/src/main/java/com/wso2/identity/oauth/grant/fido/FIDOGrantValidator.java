package com.wso2.identity.oauth.grant.fido;

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;


/**
 * This validates the fido grant request.
 */
public class FIDOGrantValidator extends AbstractValidator<HttpServletRequest> {


    public FIDOGrantValidator() {

        // grant type must be in the request parameter
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        // response object must be in the request parameter
        requiredParams.add(FIDOGrantConstants.GRANT_PARAM_RESPONSE_OBJECT);
        // username must be in the request parameter
        requiredParams.add(FIDOGrantConstants.GRANT_PARAM_USERNAME);

    }
}
