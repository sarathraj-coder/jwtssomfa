package qa.gov.customs.oauth2.appoauth.config.granter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import qa.gov.customs.oauth2.appoauth.service.MfaService;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class MfaTokenGranter extends AbstractTokenGranter {
    private static final String GRANT_TYPE = "mfa";

    private final TokenStore tokenStore;
    private final ClientDetailsService clientDetailsService;
    private final AuthenticationManager authenticationManager;
    private final MfaService mfaService;

    public MfaTokenGranter(AuthorizationServerEndpointsConfigurer endpointsConfigurer, AuthenticationManager authenticationManager, MfaService mfaService) {
        super(endpointsConfigurer.getTokenServices(), endpointsConfigurer.getClientDetailsService(), endpointsConfigurer.getOAuth2RequestFactory(), GRANT_TYPE);
        this.tokenStore = endpointsConfigurer.getTokenStore();
        this.clientDetailsService = endpointsConfigurer.getClientDetailsService();
        this.authenticationManager = authenticationManager;
        this.mfaService = mfaService;

    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        System.out.println("Parameters ==> " + tokenRequest.getRequestParameters());
        Map<String, String> parameters = new LinkedHashMap<>(tokenRequest.getRequestParameters());
        final String mfaToken = parameters.get("mfa_token");
        if (mfaToken != null) {
            OAuth2Authentication authentication = loadAuthentication(mfaToken);
            final String username = authentication.getName();
            System.out.println("UserName ----> " + username);
            if (parameters.containsKey("mfa_code")) {
                int code = parseCode(parameters.get("mfa_code"));
                if (mfaService.verifyCode(username, code)) {
                    System.out.println("getAuthentication tokenRequest " + tokenRequest);
                    System.out.println("getAuthentication authentication " + authentication);
                    OAuth2Authentication i =  getAuthentication(tokenRequest, authentication);
                    System.out.println("getAuthentication Return " + i);
                    return i;
                }
            } else {

                System.out.println("Trow 1 ==> " + "Missing MFA code");
                throw new InvalidRequestException("Missing MFA code");
            }
            System.out.println("Trow 2 ==> " + "Missing MFA code");
            throw new InvalidGrantException("Invalid MFA code");
        } else {
            System.out.println("Trow 3 ==> " + "Missing MFA code");
            throw new InvalidRequestException("Missing MFA token");
        }
    }

    private OAuth2Authentication loadAuthentication(String accessTokenValue) {

        OAuth2AccessToken accessToken = this.tokenStore.readAccessToken(accessTokenValue);
        if (accessToken == null) {
            System.out.println("Trow 4 ==> " + "Missing MFA code");
            throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
        } else if (accessToken.isExpired()) {
            this.tokenStore.removeAccessToken(accessToken);
            System.out.println("Trow 5 ==> " + "Missing MFA code");
            throw new InvalidTokenException("Access token expired: " + accessTokenValue);
        } else {
            OAuth2Authentication result = this.tokenStore.readAuthentication(accessToken);
            if (result == null) {
                System.out.println("Trow 6 ==> " + "Missing MFA code");
                throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
            }
            return result;
        }
    }

    private int parseCode(String codeString) {
        try {
            return Integer.parseInt(codeString);
        } catch (NumberFormatException e) {
            System.out.println("Trow 7 ==> " + "Missing MFA code");
            throw new InvalidGrantException("Invalid MFA code");
        }
    }

    private OAuth2Authentication getAuthentication(TokenRequest tokenRequest, OAuth2Authentication authentication) {
        try {
            System.out.println("Trow 91 ==> " + "getAuthentication" + authentication.getUserAuthentication());

            authentication.getUserAuthentication();
            Authentication user = authenticationManager.authenticate(authentication.getUserAuthentication()  );
            System.out.println("Trow 9112 ==> " + user);
            Object details = authentication.getDetails();
            authentication = new OAuth2Authentication(authentication.getOAuth2Request(), user);
            System.out.println("Trow 911 ==> " + details);
            authentication.setDetails(details);

            String clientId = authentication.getOAuth2Request().getClientId();
            System.out.println("Trow 9116 ==> " + clientId);
            if (clientId != null && clientId.equals(tokenRequest.getClientId())) {
                if (this.clientDetailsService != null) {
                    try {
                        this.clientDetailsService.loadClientByClientId(clientId);
                    } catch (ClientRegistrationException e) {
                        System.out.println("Trow 9 ==> " + "Missing MFA code");
                        throw new InvalidTokenException("Client not valid: " + clientId, e);
                    }
                }
                return refreshAuthentication(authentication, tokenRequest);
            } else {
                System.out.println("Trow 10 ==> " + "Missing MFA code");
                throw new InvalidGrantException("Client is missing or does not correspond to the MFA token");
            }
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    private OAuth2Authentication refreshAuthentication(OAuth2Authentication authentication, TokenRequest request) {
        try {
            Set<String> scope = request.getScope();
            OAuth2Request clientAuth = authentication.getOAuth2Request().refresh(request);
            System.out.println("Trow 9118 ==> " + clientAuth);
            if (scope != null && !scope.isEmpty()) {
                Set<String> originalScope = clientAuth.getScope();
                if (originalScope == null || !originalScope.containsAll(scope)) {
                    System.out.println("Trow 11 ==> " + "Missing MFA code");
                    throw new InvalidScopeException("Unable to narrow the scope of the client authentication to " + scope + ".", originalScope);
                }

                clientAuth = clientAuth.narrowScope(scope);
            }
            System.out.println("Trow 911811 ==> " + scope);
            return new OAuth2Authentication(clientAuth, authentication.getUserAuthentication());
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}