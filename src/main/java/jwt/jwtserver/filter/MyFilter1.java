package jwt.jwtserver.filter;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter1 implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;
        chain.doFilter(req, res);
        // 토큰 : cos -> ID, PW가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할 때마다 header에 Authorization에 value 값으로 토큰을 가지고 오겠죠?
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면됨
//        if(req.getMethod().equals("POST")){
//            System.out.println("POST 요청됨");
//            String authorization = req.getHeader("Authorization");
//            System.out.println("authorization = " + authorization);
//            System.out.println("필터1");
//
//            if(authorization.equals("cos")){
//                chain.doFilter(req, res);
//            }else{
//                PrintWriter writer = res.getWriter();
//                writer.println("인증 안됨");
//            }
//        }
    }
}
