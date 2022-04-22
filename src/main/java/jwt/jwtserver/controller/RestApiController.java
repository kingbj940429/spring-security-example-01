package jwt.jwtserver.controller;

import jwt.jwtserver.model.User;
import jwt.jwtserver.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class RestApiController {
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepo userRepo;

    @GetMapping("/home")
    public String name(){
        return "<h1>home</h1>";
    }

    @PostMapping ("/token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepo.save(user);

        return "회원가입완료";
    }

    @GetMapping("/api/v1/user")
    public String user() {
        System.out.println("GET /api/v1/user" );
        return "user";
    }

    @GetMapping("/api/v1/manager")
    public String manager() {
        return "manager";
    }
    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }
}
