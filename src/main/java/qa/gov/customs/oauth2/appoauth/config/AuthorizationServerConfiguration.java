package qa.gov.customs.oauth2.appoauth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import qa.gov.customs.oauth2.appoauth.config.granter.MfaTokenGranter;
import qa.gov.customs.oauth2.appoauth.config.granter.PasswordTokenGranter;
import qa.gov.customs.oauth2.appoauth.service.MfaService;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Configuration
public class AuthorizationServerConfiguration implements AuthorizationServerConfigurer {


    @Autowired
    UserDetailsService userDetailsService;


    @Autowired
    DataSource dataSource;


    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private MfaService mfaService;

    @Autowired
    public AuthorizationServerConfiguration(PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager,
                                            MfaService mfaService) {
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.mfaService = mfaService;
    }


    @Bean
    TokenStore jwtTokenStore(){
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setAccessTokenConverter(new CustomAccessTokenConverter());
        converter.setKeyPair(new KeyStoreKeyFactory(new ClassPathResource("jwt1.jks"), "password".toCharArray()).getKeyPair("jwt"));
        return converter;
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()").tokenKeyAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.jdbc(dataSource).passwordEncoder(passwordEncoder);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      // endpoints.authenticationManager(authenticationManager);
      //  endpoints .authenticationManager(authenticationManagerBean);
      //  endpoints.userDetailsService(userDetailsService);
        endpoints.tokenGranter(tokenGranter(endpoints));
    }


    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {

        ArrayList<TokenEnhancer> enhancers =  new ArrayList<>();
        enhancers.add(new CustomTokenEnhancer());
        enhancers.add(accessTokenConverter());
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(enhancers);


        endpoints.tokenStore(jwtTokenStore());
        endpoints.accessTokenConverter(accessTokenConverter());
        endpoints.tokenEnhancer(tokenEnhancerChain);

        //endpoints.authenticationManager(authenticationManager);



        //endpoints .authenticationManager(authenticationManager);
       // endpoints.userDetailsService(userDetailsService);
        List<TokenGranter> granters = new ArrayList<>();
        granters.add(endpoints.getTokenGranter());
        granters.add(new PasswordTokenGranter(endpoints, authenticationManager, mfaService));
        granters.add(new MfaTokenGranter(endpoints, authenticationManager, mfaService));
        //granters.add(new MfaTokenGranter(endpoints, authenticationManagerBean, mfaService));
        return new CompositeTokenGranter(granters);
    }
}
