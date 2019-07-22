package com.emles.configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import javax.sql.DataSource;

@EnableResourceServer
@Configuration
public class OauthResourcesServerConfiguration extends ResourceServerConfigurerAdapter {

	
	@Value("${spring.redis.host}")
	private String redisHost;
	
	@Value("${spring.redis.port}")
	private int redisPort;
	
	@Autowired
	private TokenStore tokenStore;
	
    @Autowired
    public DataSource ouathDataSource;

    @Override
    public void configure (ResourceServerSecurityConfigurer resources) throws Exception{
        resources.resourceId("oauth_server_api").tokenStore(tokenStore);
    }
    
    @Override
    public void configure(HttpSecurity http) throws Exception{
        http
        .authorizeRequests()
        .antMatchers(HttpMethod.GET, "/**").access("#oauth2.hasScope('read')")
        .antMatchers(HttpMethod.POST, "/**").access("#oauth2.hasScope('write')")
        .antMatchers(HttpMethod.PATCH, "/**").access("#oauth2.hasScope('write')")
        .antMatchers(HttpMethod.PUT, "/**").access("#oauth2.hasScope('write')")
        .antMatchers(HttpMethod.DELETE, "/**").access("#oauth2.hasScope('write')")
        .and()
        .headers().addHeaderWriter((request, response) -> {
            response.addHeader("Access-Control-Allow-Origin", "*");
            if (request.getMethod().equals("OPTIONS")) {
                response.setHeader("Access-Control-Allow-Methods", request.getHeader("Access-Control-Request-Method"));
                response.setHeader("Access-Control-Allow-Headers", request.getHeader("Access-Control-Request-Headers"));
            }
        });
    }
}