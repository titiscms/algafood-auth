package com.algaworks.algafoog.auth.core;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		
		if (authentication.getPrincipal() instanceof AuthUser) {
			AuthUser authUser = (AuthUser) authentication.getPrincipal();
			
			Map<String, Object> info = new HashMap<String, Object>();
			info.put("nome_completo", authUser.getFullname());
			info.put("usuario_id", authUser.getUserId());
			
			DefaultOAuth2AccessToken oAuthAccessToken = (DefaultOAuth2AccessToken) accessToken;
			oAuthAccessToken.setAdditionalInformation(info);
		}
		
		return accessToken;
	}

}
