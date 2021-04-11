package com.algaworks.algafoog.auth.core;

import java.security.KeyPair;
import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;

	/*
	 * Desabilitado temporariamente
	 * configuração para usar o redis para armazenar os tokens
	 */
//	@Autowired
//	private RedisConnectionFactory redisConnectionFactory;
	
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
				/*
				 * configurando para não precisar passar o client_secret como query params
				 * usando o PKCE 
				 */
				.secret(passwordEncoder.encode(""))
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
		/*
		 * Instanciação de cadeia de incremento do token
		 */
		TokenEnhancerChain enharcerChain = new TokenEnhancerChain();
		enharcerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			/*
			 * configuração para inutilizar o reuso do refresh token.
			 */
			.reuseRefreshTokens(false)
			/*
			 * configuração de conversor de access_token para jwt (tokens transparentes)
			 */
			.accessTokenConverter(jwtAccessTokenConverter())
			/*
			 * configuração para customizar as informações no payload do token
			 */
			.tokenEnhancer(enharcerChain)
			/*
			 * Configuração de aprovação granular dos escopos
			 */
			.approvalStore(approvalStore(endpoints.getTokenStore()))
			/*
			 * Desabilitado temporariamente
			 * configuração para usar o redis para armazenar os tokens
			 */
//			.tokenStore(redisTokenStore())
			/*
			 * configuração para usar o pkce
			 */
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		TokenApprovalStore approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
//		security.checkTokenAccess("isAuthenticated()");
		security
			.checkTokenAccess("permitAll()")
				/*
				 * configuração para liberar acesso que retorna a chave publica 
				 */
				.tokenKeyAccess("permitAll()")
				/*
				 * configuração para permitir passar a autenticação via query params na url.
				 */
				.allowFormAuthenticationForClients();
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		/*
		 * configuração para trabalhar com chave simétrica
		 */
//		jwtAccessTokenConverter.setSigningKey("oaiheknadcliaecadkcfkvnefoidfhdbs98euonwdnvlksjoi3");
		
		/*
		 * configuração para trabalhar com chave assimétrica
		 */
		ClassPathResource jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		String keyStorePass = jwtKeyStoreProperties.getPassword();
		String keyPairAlias = jwtKeyStoreProperties.getAlias();
		
		KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		KeyPair keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		
		return jwtAccessTokenConverter;
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

	/*
	 * Desabilitado temporariamente
	 * configuração para usar o redis para armazenar os tokens
	 */
//	private TokenStore redisTokenStore() {
//		return new RedisTokenStore(redisConnectionFactory);
//	}
		
}
