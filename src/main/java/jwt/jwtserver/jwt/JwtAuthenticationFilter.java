package jwt.jwtserver.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jwt.jwtserver.auth.PrincipalDetails;
import jwt.jwtserver.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// /login 요청해서 username, password 전송하면(post)
// 아래가 동작을 하게됨 하지만 .formLogin().disable() 때문에 동작을 안하게됨 -> 따라서 아래처럼 하게 해주어야 함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // 얘가 실질적으로 username, password 받아서 로그인 처리를 해줌
    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        // 1. username, password 받아서
        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면!!
        // PrincipalDetailService가 호출됨 그러면 loadUserByUsername가 실행됨
        // 3. PrincipaDetails를 세션에 담고 (권한 관리를 위해서, 권한 관리 필요없으면 이 과정 필요 없음)
        // 4. JWT 토큰을 만들어서 응답해주면 됨.
        try {
            ObjectMapper om = new ObjectMapper(); // 이게 json을 파싱해준다.
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 여기서 PrincipalService의 loadUserByUsername가 실행됨 => 정상이면 authentication가 리턴됨
            // DB에 있는 username과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken); // 얘를 해주는 이유는 권한 처리 때문에 해주는 거임, 만약 권한이 없는 JWT 라면 굳이 필요 없음

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("principalDetails = " + principalDetails.getUser().getUsername()); // 얘가 출력되면 로그인이 잘 되었다는 뜻

            // 리턴해줌으로써 authentication 객체가 session 영역에 저장됨
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 거임
            // jwt 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 session에 넣어 준다.

            // 리턴해주기 전에 마지막으로 JWT 토큰을 만들어 줘야함 -> 근데 굳이 여기서 안만들어도됨. attemptAuthentication가 끝나면 실행되는 함수가 있음. 그게 아래에 successfulAuthentication임
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 완료되면 successfulAuthentication가 실행됨
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        //RSA 방식은 아니고 HMAC512 방식이다.
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10))) // 현재 시간 + 10분
                .withClaim("id", principalDetails.getUser().getId()) // 넣고 싶은 키 값을 넣는 거임
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));// 시크릿키 값이 들어가야함

        response.addHeader("Authorization", "Bearer " + jwtToken);
        //super.successfulAuthentication(request, response, chain, authResult);

        /*
        1. 유저 네임, 패스워드 로그인 정상
        2. JWT 토큰을 생성
        3. 클라이언트 쪽으로 JWT 토큰을 응답
        4. 요청할 때마다 JWT 토큰을 가지고 요청
        5. 서버는 JWT 토큰이 유효한지를 판단 -> 이에 대한 필터를 만들어줘야함.
         */
    }
}
