package jwt.jwtserver.auth;

import jwt.jwtserver.model.User;
import jwt.jwtserver.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/*
http://localhost:8080/login => 동작을 안함. 왜냐 .formLogin().disable() 때문에 // JwtAuthenticationFilter 참고
 */
@Service
@RequiredArgsConstructor
public class PrincipalService implements UserDetailsService {

    private final UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalService의 loadUserByUsername()");
        User userEntity = userRepo.findByUsername(username);

        return new PrincipalDetails(userEntity);
    }
}
