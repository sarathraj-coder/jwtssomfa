package qa.gov.customs.oauth2.appoauth.service;

import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
@Service
public class MfaService {

    //TODO this class to be updated
    private static final Map<String, String> SECRET_BY_USERNAME =getUser();

    static Map<String, String> getUser(){
     Map<String, String> userTest =new HashMap<>();
        userTest.put("krish","1234");
        return  userTest;
    }


    public boolean isEnabled(String username) {
        return SECRET_BY_USERNAME.containsKey(username);
    }

    public boolean verifyCode(String username, int code) {
        System.out.println("usernameusernameusernameusernameusername ====> " + username);
        System.out.println("code code code  ====> " + code);
        return code == 1234;
    }
}
