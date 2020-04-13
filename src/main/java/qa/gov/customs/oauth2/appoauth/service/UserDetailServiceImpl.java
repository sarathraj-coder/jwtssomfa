package qa.gov.customs.oauth2.appoauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import qa.gov.customs.oauth2.appoauth.model.AuthUserDetail;
import qa.gov.customs.oauth2.appoauth.model.User;
import qa.gov.customs.oauth2.appoauth.repository.UserDetailsRepository;


import java.util.Optional;

@Service("userDetailsService")
public class UserDetailServiceImpl implements UserDetailsService {


    @Autowired
    private UserDetailsRepository userDetailsRepository;

    @Override
    public UserDetails loadUserByUsername(String name) throws UsernameNotFoundException {
       Optional<User> user = userDetailsRepository.findByUsername(name);

       user.orElseThrow(()-> new UsernameNotFoundException("User not found"));

       UserDetails userDetails = new AuthUserDetail(user.get());

       new AccountStatusUserDetailsChecker().check(userDetails);

       System.out.println("After user is ok ");
       return userDetails;
    }
}
