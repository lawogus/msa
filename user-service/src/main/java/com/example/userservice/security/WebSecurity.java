package com.example.userservice.security;

import com.example.userservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class WebSecurity {
    private UserService userService;
    private AuthenticationConfiguration authenticationConfiguration;
    private Environment env;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public WebSecurity(UserService userService, AuthenticationConfiguration authenticationConfiguration, Environment env, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.authenticationConfiguration = authenticationConfiguration;
        this.env = env;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    /**
     * Spring Security 5.7.x 부터 WebSecurityConfigurerAdapter 는 Deprecated.
     * -> SecurityFilterChain, WebSecurityCustomizer 를 상황에 따라 빈으로 등록해 사용한다.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(request -> {
//                    request.anyRequest().permitAll();
                    request.requestMatchers("/**").permitAll();
                })
                .addFilter(getAuthenticationFilter())
                .headers(headers -> {
                    headers.frameOptions(frameOptions -> {
                        frameOptions.disable();
                    });
                });
        return http.build();
    }

    @Bean
    public AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationFilter authenticationFilter =
                new AuthenticationFilter(authenticationManager(),userService, env);
//        authenticationFilter.setAuthenticationManager(authenticationManager());
        return authenticationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager() throws Exception{
        return this.authenticationConfiguration.getAuthenticationManager();
    }

    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
        return auth.build();
    }


}
