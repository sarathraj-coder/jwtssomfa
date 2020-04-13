package qa.gov.customs.oauth2.appoauth.config.granter;

import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import qa.gov.customs.oauth2.appoauth.service.MfaService;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class PasswordTokenGranter extends AbstractTokenGranter {
    private static final String GRANT_TYPE = "password";
    private static final GrantedAuthority PRE_AUTH = new SimpleGrantedAuthority("PRE_AUTH");

    private final AuthenticationManager authenticationManager;
    private final MfaService mfaService;

    public PasswordTokenGranter(AuthorizationServerEndpointsConfigurer endpointsConfigurer, AuthenticationManager authenticationManager, MfaService mfaService) {
        super(endpointsConfigurer.getTokenServices(), endpointsConfigurer.getClientDetailsService(), endpointsConfigurer.getOAuth2RequestFactory(), GRANT_TYPE);
        this.authenticationManager = authenticationManager;
        this.mfaService = mfaService;

    }

    //TODO  Starting from here ..
    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        String username = parameters.get("username");
        String password = parameters.get("password");
        parameters.remove("password");
        //TODO send SMS from here
        //TODO save code to the server DB with expiration
        System.out.println("After user is ok send SMS 1234");
        Authentication userAuth = new UsernamePasswordAuthenticationToken(username, password);
        //userAuth.
        ((AbstractAuthenticationToken) userAuth).setDetails(parameters);

        try {
            userAuth = this.authenticationManager.authenticate(userAuth);
        } catch (AccountStatusException | BadCredentialsException e) {
            throw new InvalidGrantException(e.getMessage());
        }

        if (userAuth != null && userAuth.isAuthenticated()) {
            OAuth2Request storedOAuth2Request = this.getRequestFactory().createOAuth2Request(client, tokenRequest);
            if (mfaService.isEnabled(username)) {
                userAuth = new UsernamePasswordAuthenticationToken(username, password, Collections.singleton(PRE_AUTH));
                OAuth2AccessToken accessToken = getTokenServices().createAccessToken(new OAuth2Authentication(storedOAuth2Request, userAuth));
                throw new MfaRequiredException(accessToken.getValue());
            }
            return new OAuth2Authentication(storedOAuth2Request, userAuth);
        } else {
            throw new InvalidGrantException("Could not authenticate user: " + username);
        }
    }
}