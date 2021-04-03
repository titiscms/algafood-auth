package com.algaworks.algafoog.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				/*
				 * configuração para usar o fluxo password grant_type + refresh-token
				 */
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				/*
				 * configuração para definir o tempo de vida do access-token para 1 minutos
				 * access_token: valor em segundos e padrão é de 12 horas.
				 */
				.accessTokenValiditySeconds(60)
				/*
				 * configuração para definir o tempo de vida do refresh-token para 3 minutos
				 * refresh_token: valor em segundos e padrão é de 30 dias.
				 */
				.refreshTokenValiditySeconds(60 * 3)
				
			.and()
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				/*
				 * configuração para usar o fluxo client_credentials grant_type
				 * deixando o tempo de vida do access-token padrão 
				 */
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read")
				
			.and()
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode("food123"))
				/*
				 * configuração para usar o fluxo authorization_code grant_type
				 * deixando o tempo de vida do access-token padrão 
				 */
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://www.foodanalytics.local:8082")
				
			.and()
				.withClient("logistica")
				/*
				 * configuração para usar o fluxo implicit grant_type
				 * não requer autenticação do cliente
				 * deixando o tempo de vida do access-token padrão 
				 */
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://www.foodlogistics.local:8082")	
				
			.and()
				.withClient("algafood-mobile")
				.secret(passwordEncoder.encode("mobile123"))
				.authorizedGrantTypes("password")
				.scopes("write", "read")
				/*
				 * configuração para definir o tempo de vida do refresh-token para 6 horas
				 */
				.accessTokenValiditySeconds(60 * 60 * 6)
				/*
				 * configuração para definir o tempo de vida do refresh-token para 60 dias
				 */
				.accessTokenValiditySeconds(60 * 60 * 24 * 60)
				
			.and()
				/*
				 * configuração de acesso do resource server ao authorization server
				 */
				.withClient("algafood-check-token")
				.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			/*
			 * configuração para inutilizar o reuso do refresh token.
			 */
			.reuseRefreshTokens(false)
			/*
			 * configuração para usar o pkce
			 */
			.tokenGranter(tokenGranter(endpoints));;
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security.checkTokenAccess("permitAll()")
			/*
			 * configuração para permitir passar a autenticação via query params na url.
			 */
			.allowFormAuthenticationForClients();
	}
	
	/*
	 * Método para suportar o PKCE no projeto
	 */
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
		
}
