package com.algaworks.algafoog.auth.core;

import java.security.KeyPair;
import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
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

	/*
	 * private static final String SCOPE_TYPE_READ = "READ";
	 * 
	 * private static final String SCOPE_TYPE_WRITE = "WRITE";
	 * 
	 * @Autowired private PasswordEncoder passwordEncoder;
	 */
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	@Autowired
	private DataSource dataSource;

	/*
	 * Desabilitado temporariamente
	 * configura????o para usar o redis para armazenar os tokens
	 */
//	@Autowired
//	private RedisConnectionFactory redisConnectionFactory;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.jdbc(dataSource);
		
		// implementa????o de configura????o de clients em memoria.
//			.inMemory()
//				.withClient("algafood-web")
//				.secret(passwordEncoder.encode("web123"))
//				/*
//				 * configura????o para usar o fluxo password grant_type + refresh-token
//				 */
//				.authorizedGrantTypes("password", "refresh_token")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				/*
//				 * configura????o para definir o tempo de vida do access-token para 1 minutos
//				 * access_token: valor em segundos e padr??o ?? de 12 horas.
//				 */
//				.accessTokenValiditySeconds(60)
//				/*
//				 * configura????o para definir o tempo de vida do refresh-token para 3 minutos
//				 * refresh_token: valor em segundos e padr??o ?? de 30 dias.
//				 */
//				.refreshTokenValiditySeconds(60 * 3)
//				
//			.and()
//				.withClient("faturamento")
//				.secret(passwordEncoder.encode("faturamento123"))
//				/*
//				 * configura????o para usar o fluxo client_credentials grant_type
//				 * deixando o tempo de vida do access-token padr??o 
//				 */
//				.authorizedGrantTypes("client_credentials")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				
//			.and()
//				.withClient("foodanalyticssimple")
//				.secret(passwordEncoder.encode("food123"))
//				/*
//				 * configura????o para usar o fluxo authorization_code grant_type
//				 * deixando o tempo de vida do access-token padr??o 
//				 */
//				.authorizedGrantTypes("authorization_code")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				.redirectUris("http://www.foodanalytics.local:8082")
//				
//			.and()
//				.withClient("foodanalytics")
//				/*
//				 * configurando para n??o precisar passar o client_secret como query params
//				 * usando o PKCE 
//				 */
//				.secret(passwordEncoder.encode(""))
//				/*
//				 * configura????o para usar o fluxo authorization_code grant_type
//				 * deixando o tempo de vida do access-token padr??o 
//				 */
//				.authorizedGrantTypes("authorization_code")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				.redirectUris("http://www.foodanalytics.local:8082")	
//				
//			.and()
//				.withClient("logistica")
//				/*
//				 * configura????o para usar o fluxo implicit grant_type
//				 * n??o requer autentica????o do cliente
//				 * deixando o tempo de vida do access-token padr??o 
//				 */
//				.authorizedGrantTypes("implicit")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				.redirectUris("http://www.foodlogistics.local:8082")	
//				
//			.and()
//				.withClient("algafood-mobile")
//				.secret(passwordEncoder.encode("mobile123"))
//				.authorizedGrantTypes("password")
//				.scopes(SCOPE_TYPE_WRITE, SCOPE_TYPE_READ)
//				/*
//				 * configura????o para definir o tempo de vida do refresh-token para 6 horas
//				 */
//				.accessTokenValiditySeconds(60 * 60 * 6)
//				/*
//				 * configura????o para definir o tempo de vida do refresh-token para 60 dias
//				 */
//				.accessTokenValiditySeconds(60 * 60 * 24 * 60)
//				
//			.and()
//				/*
//				 * configura????o de acesso do resource server ao authorization server
//				 */
//				.withClient("algafood-check-token")
//				.secret(passwordEncoder.encode("check123"));
		
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		/*
		 * Instancia????o de cadeia de incremento do token
		 */
		TokenEnhancerChain enharcerChain = new TokenEnhancerChain();
		enharcerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			/*
			 * configura????o para inutilizar o reuso do refresh token.
			 */
			.reuseRefreshTokens(false)
			/*
			 * configura????o de conversor de access_token para jwt (tokens transparentes)
			 */
			.accessTokenConverter(jwtAccessTokenConverter())
			/*
			 * configura????o para customizar as informa????es no payload do token
			 */
			.tokenEnhancer(enharcerChain)
			/*
			 * Configura????o de aprova????o granular dos escopos
			 */
			.approvalStore(approvalStore(endpoints.getTokenStore()))
			/*
			 * Desabilitado temporariamente
			 * configura????o para usar o redis para armazenar os tokens
			 */
//			.tokenStore(redisTokenStore())
			/*
			 * configura????o para usar o pkce
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
				 * configura????o para liberar acesso que retorna a chave publica 
				 */
				.tokenKeyAccess("permitAll()")
				/*
				 * configura????o para permitir passar a autentica????o via query params na url.
				 */
				.allowFormAuthenticationForClients();
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		/*
		 * configura????o para trabalhar com chave sim??trica
		 */
//		jwtAccessTokenConverter.setSigningKey("oaiheknadcliaecadkcfkvnefoidfhdbs98euonwdnvlksjoi3");
		
		/*
		 * configura????o para trabalhar com chave assim??trica
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
	 * M??todo para suportar o PKCE no projeto
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
	 * configura????o para usar o redis para armazenar os tokens
	 */
//	private TokenStore redisTokenStore() {
//		return new RedisTokenStore(redisConnectionFactory);
//	}
		
}
