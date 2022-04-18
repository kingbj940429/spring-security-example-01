package jwt.jwtserver.config;

import jwt.jwtserver.filter.MyFilter1;
import jwt.jwtserver.filter.MyFilter2;
import jwt.jwtserver.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final CorsFilter corsFilter;

    @Override
     protected void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);// 굳이 이렇게 필터를 걸 필요가 없다. => FilterConfig에 걸기, FilterConfig에 있는 필터랑 누가 더 빨리 출력될까?
        // addFilterBefore After 이든 시큐리티 필터체인이 FilterConfig보다 먼저 실행된다.

        http.addFilterBefore(new MyFilter1(), SecurityContextPersistenceFilter.class);
        // 이렇게 순서도 정할수 있다. SecurityContextPersistenceFilter 이 클래스가 BasicAuthenticationFilter보다 먼저 실행되는 필터이다.
        // security-order.png 참고

        http.csrf().disable();

        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 사용하지 않겠음
                .and()
                .addFilter(corsFilter) // 서버로 오는 모든 요청을 여기서 처리함 @CrossOrigin으로 해결 가능하지만 이건 전체에다 걸수가 없음.
                // @CrossOrigin은 인증X, 시큐리티 필터는 등록 인증 O
                .formLogin().disable() // 폼 로그인 사용안함 => jwt 사용할 때 일케함
                .httpBasic().disable() // 기본적인 http 로그인 방식을 아예 사용하지 않음 => jwt 사용할 때 일케함. httpBasic이 아니라 Bearer를 사용하겠다.
                // http only를 false 해줘야 임의로 쿠키를 보낼수 없다. -> 보안에 좋다.
                // httpBasic는 header의 authorization 부분에 ID와 PW를 같이 보내게 되는데 평문화되서 보안이 좋지 않다. -> https를 사용해야 한다. 아이디와 패스워드가 암호화됨
                // authorization에 토큰을 넣는 방식이 JWT 방식이다.
                // Basic => ID와 PW를 가지고 있는 방식
                // Bearer => Token을 가지고 있는 방식
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
