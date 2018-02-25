package com.application.springSecurity.businessLayer;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;

/**
 * Model to demonstrate a security configuration over bean
 * @author Ihor Savchenko
 * @version 1.0
 */
@Component("beanSecurity")
public class BeanSecurity {

    public boolean check(Authentication authentication) {

        if (!(authentication instanceof AnonymousAuthenticationToken)) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            for (GrantedAuthority author : authorities) {
                if (author.getAuthority().equals("ROLE_ADMIN")) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }
}
