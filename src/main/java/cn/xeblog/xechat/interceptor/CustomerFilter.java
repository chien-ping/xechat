package cn.xeblog.xechat.interceptor;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

/**
 * 权限校验拦截器
 *
 * @author yanpanyi
 * @date 2019/4/5
 */
@Component
@Slf4j
public class CustomerFilter extends GenericFilterBean {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

        //驗證客戶來源
        if (httpRequest.getRequestURI().contains("/customer")) {
            log.warn("customer uri: {}", httpRequest.getRequestURI());
            String uid = httpRequest.getParameter("uid");
            String userId = httpRequest.getParameter("userId");
            String userName = httpRequest.getParameter("userName");

            UserDetails userDetails = User.builder()
                    .username("userName")
                    .password("")
                    .roles("USER")
                    .build();

            //將用戶放入Authentication物件，代表已通過驗證
            Authentication auth=new UsernamePasswordAuthenticationToken(userDetails,
                    userDetails.getPassword(), userDetails.getAuthorities());
            //將Authentication物件放入SecurityContext存放
            SecurityContext sc = SecurityContextHolder.getContext();
            sc.setAuthentication(auth);
            //將SecurityContext放到session，模擬登入
            HttpSession session = httpRequest.getSession(true);
            session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
