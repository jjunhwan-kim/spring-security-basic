package io.security.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        formLogin(http);
        formLogout(http);
        rememberMe(http);
        sessionManagement(http);
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

    private void formLogout(HttpSecurity http) throws Exception {
        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me");
    }

    private void rememberMe(HttpSecurity http) throws Exception {
        http
                .rememberMe()
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600)      // Default는 14일
                .alwaysRemember(false)           // true일 경우 리멤버 미 기능이 활성화되지 않아도 항상 실행
                .userDetailsService(userDetailsService);
    }

    private void sessionManagement(HttpSecurity http) throws Exception {
        http    // 동시 세션 제어
                .sessionManagement()
                .maximumSessions(1)              // 최대 허용 가능 세션 수 (-1: 무제한 로그인 세션 허용)
                .maxSessionsPreventsLogin(false) // 동시 로그인 차단함(false: 기존 세션 만료(default))
                .expiredUrl("/expired");

        http    // 세션 고정 보호
                .sessionManagement()
                .sessionFixation()
                .changeSessionId(); // 기본 값(none, changeSessionId, newSession, migrateSession)

        http    // 세션 정책
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED); // 기본 값

        // SessionCreationPolicy.ALWAYS: 스프링 시큐리티가 항상 세션 생성
        // SessionCreationPolicy.NEVER: 스프링 시큐리티가 생성하지 않지만 이미 존재하면 사용
        // SessionCreationPolicy.IF_REQUIRED: 스프링 시큐리티가 필요 시 생성(기본값)
        // SessionCreationPolicy.STATELESS: 스프링 시큐리티가 생성하지 않고 존재해도 사용하지 않음
    }
}
