package qa.gov.customs.oauth2.appoauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@SpringBootApplication
@EnableAuthorizationServer
public class AppOauthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AppOauthApplication.class, args);
    }

}
