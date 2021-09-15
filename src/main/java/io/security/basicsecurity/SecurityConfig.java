package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        formLogin(http);
    }

    private void formLogin(HttpSecurity http) throws Exception {
        http
                .formLogin()                     // Form Login 인증
                //.loginPage("/loginPage")       // 사용자 정의 로그인 페이지, 미사용시 기본 페이지 제공
                .defaultSuccessUrl("/home")      // 로그인 성공 후 이동 페이지(기본 값, 우선순위는 가장 낮음)
                .failureUrl("/loginPage")        // 로그인 실패 후 이동 페이지
                .usernameParameter("username")   // 아이디 파라미터명 설정
                .passwordParameter("password")   // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login")    // 로그인 Form Action URL
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 핸들러
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication= " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 핸들러
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception= " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // 로그인 페이지는 인증을 받지 않아도 접근이 가능하도록 설정해야함
    }
}
