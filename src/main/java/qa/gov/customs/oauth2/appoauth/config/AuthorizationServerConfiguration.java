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

    @Bean
    public PasswordEncoder passwordEncoder() throws Exception {
        return  PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    TokenStore jwtTokenStore(){
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new CustomTokenEnhancer();
        converter.setKeyPair(new KeyStoreKeyFactory(new ClassPathResource("jwt1.jks"), "password".toCharArray()).getKeyPair("jwt"));
        return converter;
    }


    @Bean
    TokenStore jdbcTokenStore(){
        //return new JwtTokenStore(jwtAccessTokenConverter());
       return new JdbcTokenStore(dataSource);
    }


    @Autowired
    DataSource dataSource;

    @Autowired
    AuthenticationManager authenticationManagerBean;





    @Autowired
    private MfaService mfaService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.checkTokenAccess("isAuthenticated()").tokenKeyAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.jdbc(dataSource).passwordEncoder(passwordEncoder());
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
      // endpoints.authenticationManager(authenticationManager);
      //  endpoints .authenticationManager(authenticationManagerBean);
      //  endpoints.userDetailsService(userDetailsService);
        endpoints.tokenGranter(tokenGranter(endpoints));
    }


    private TokenGranter tokenGranter(final AuthorizationServerEndpointsConfigurer endpoints) {
        System.out.println("Here the issue 3");
        endpoints.tokenStore(jwtTokenStore());
        //endpoints .reuseRefreshTokens(false);
        endpoints.accessTokenConverter(jwtAccessTokenConverter());
        //endpoints.tokenEnhancer(jwtAccessTokenConverter());
        //endpoints.tokenServices(endpoints.getTokenServices());



        //endpoints .authenticationManager(authenticationManager);
        endpoints.userDetailsService(userDetailsService);
        List<TokenGranter> granters = new ArrayList<>();
        granters.add(endpoints.getTokenGranter());
        granters.add(new PasswordTokenGranter(endpoints, authenticationManagerBean, mfaService));
        granters.add(new MfaTokenGranter(endpoints, authenticationManagerBean, mfaService));
        //granters.add(new MfaTokenGranter(endpoints, authenticationManagerBean, mfaService));
        return new CompositeTokenGranter(granters);
    }
}
