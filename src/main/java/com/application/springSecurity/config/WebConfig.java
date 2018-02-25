package com.application.springSecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;

/**
 * Java configuration of a Web Servlet context
 * @author Ihor Savchenko
 * @version 1.0
 */
@EnableWebMvc
@EnableGlobalMethodSecurity(prePostEnabled = true)
@ComponentScan({"com.application.springSecurity.controller", "com.application.springSecurity.businessLayer"})
public class WebConfig implements WebMvcConfigurer {

    @Bean
    public InternalResourceViewResolver setupViewResolver() {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/WEB-INF/pages/");
        resolver.setSuffix(".jsp");

        return resolver;
    }
}
