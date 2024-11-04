package com.ericsson.ei.frontend.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

import com.azure.spring.cloud.autoconfigure.aad.AadWebSecurityConfigurerAdapter;

@Configuration
@ConditionalOnProperty(name = "spring.cloud.azure.active-directory.enabled", havingValue = "true")
public class AzureAdSecurityConfig extends AadWebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http
            .csrf().disable()
            .authorizeRequests()
         // Allow all GET requests to users with any authority
            .antMatchers(HttpMethod.GET, "/subscriptions", "/subscriptions/*", 
                         "/templates/*", "/authentication", "/authentication/*",
                         "/aggregated-objects/*", "/failed-notifications", "/aggregated-objects/query", 
                         "/rules", "/status", "/rule-test","/information")
            .hasAnyAuthority("APPROLE_Admin","APPROLE_Read","APPROLE_Write")
            // Restrict POST requests to Admin and Write roles only
            .antMatchers(HttpMethod.POST, "/subscriptions", "/rule-test/run-full-aggregation", "/aggregated-objects/query")
            .hasAnyAuthority("APPROLE_Admin", "APPROLE_Write")
            // Restrict PUT requests to Admin and Write roles only
            .antMatchers(HttpMethod.PUT, "/subscriptions")
            .hasAnyAuthority("APPROLE_Admin","APPROLE_Write")
            // Restrict PUT requests to Admin and Write roles only
            .antMatchers(HttpMethod.DELETE, "/subscriptions")
            .hasAnyAuthority("APPROLE_Admin","APPROLE_Write")
            .anyRequest().authenticated()
            .and()
            .logout();
    }
}


