package com.application.springSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * Java configuration of a Spring Security context
 * @author Ihor Savchenko
 * @version 1.0
 */
@EnableWebSecurity
@ComponentScan("com.application.springSecurity.businessLayer")
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withDefaultPasswordEncoder()
                .username("user").password("password").roles("USER").build());
        manager.createUser(User.withDefaultPasswordEncoder()
                .username("admin").password("admin").roles("ADMIN").build());
        return manager;
    }

    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .passwordEncoder(getPasswordEncoder())
                .withUser("user").password(getPasswordEncoder().encode("password"))
                .authorities("ROLE_USER")
                .and()
                .withUser("admin").password(getPasswordEncoder().encode("admin"))
                .authorities("ROLE_ADMIN");
    }*/

    protected void configure(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .antMatchers("/admin/auth").hasAuthority("ROLE_ADMIN")
                .antMatchers("/auth").hasAnyAuthority("ROLE_ADMIN","ROLE_USER")
                .antMatchers("/permit").permitAll()
                .antMatchers("/forbid").denyAll()
                .antMatchers("/anonymous").anonymous()
                .antMatchers("/authenticated").authenticated()
                .antMatchers("/fullyAuthenticated").fullyAuthenticated()
                .antMatchers("/rememberMe").rememberMe()
                .antMatchers("/beanSecurity").access("@beanSecurity.check(authentication)")
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                .rememberMe().key("secretKey").tokenValiditySeconds(2419200)
                .and()
                .logout().permitAll().logoutUrl("/logout");
                /*.and()
                .csrf().disable();*/
        http
                .requiresChannel()
                .antMatchers("/").requiresInsecure()
                .antMatchers("/**").requiresSecure();
        /*http
                .sessionManagement()
                .sessionFixation()
                .none();*/

    }

    /*private PasswordEncoder getPasswordEncoder(){

        //return NoOpPasswordEncoder.getInstance();
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder(12);
        return bCryptPasswordEncoder;
    }*/

}