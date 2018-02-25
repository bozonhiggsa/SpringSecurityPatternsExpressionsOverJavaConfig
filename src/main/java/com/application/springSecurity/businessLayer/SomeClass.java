package com.application.springSecurity.businessLayer;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;

/**
 * Model to demonstrate @PreAuthorize
 * @author Ihor Savchenko
 * @version 1.0
 */
@Component
public class SomeClass {

    @PreAuthorize("hasRole('ADMIN')")
    public boolean externalMethod() {
        return true;
    }
}
