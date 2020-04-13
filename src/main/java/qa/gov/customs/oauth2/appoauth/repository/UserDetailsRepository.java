package qa.gov.customs.oauth2.appoauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import qa.gov.customs.oauth2.appoauth.model.User;

import java.util.Optional;

public interface UserDetailsRepository extends JpaRepository<User,Long> {

    Optional<User> findByUsername(String username);
}
