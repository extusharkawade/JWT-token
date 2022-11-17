package io.getarrays.userservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager)
    {
        log.info("in CustomAuthenticationFilter");
        this.authenticationManager=authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is {} and password is {}",username,password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        log.info(authenticationToken.toString());
      log.info(String.valueOf(authenticationManager.authenticate(authenticationToken)));
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        log.info("in CustomAuthenticationFilter successfulAuthentication");
        User user = (User) authentication.getPrincipal();
        Algorithm algorithm = Algorithm.HMAC256("secreat".getBytes());
        String access_token = JWT.create().withSubject(user.getUsername())
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);


//        String temp_access_token = JWT.create().withSubject("TonyStark")
//                .withSubject(user.getUsername())
//                .withExpiresAt(new Date(System.currentTimeMillis()+10*60*1000))
//                .withIssuer(request.getRequestURI().toString())
//                .withClaim("roles",user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
//                .sign(algorithm);
//        log.info("I am temp access token"+temp_access_token);

        log.info("in CustomAuthenticationFilter successfulAuthentication access token generated"+access_token);

        String refresh_token = JWT.create().withSubject(user.getUsername())
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+30*60*1000))
                .withIssuer(request.getRequestURI().toString())
                .sign(algorithm);

        log.info("in CustomAuthenticationFilter successfulAuthentication refresh token generated"+refresh_token);

//        response.setHeader("access_token",access_token);
//        response.setHeader("refresh_token",refresh_token);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token",access_token);
        tokens.put("refresh_token",refresh_token);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(),tokens);

    }
}
