package com.enonic.cms.plugin.google.login;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Userinfo;

final class GoogleAuthorization
{
    private static final Logger LOG = Logger.getLogger( "google-login-plugin" );

    private static HttpTransport httpClientTransport;

    private static final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

    // what to ask from google
    private static final List<String> SCOPES =
        Arrays.asList( "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email" );

    private GoogleAuthorizationCodeFlow flow;

    private String redirectUrl = null;

    public GoogleAuthorization()
    {
        try
        {
            final GoogleClientSecrets clientSecrets = GoogleClientSecrets.load( JSON_FACTORY, new InputStreamReader(
                GoogleAuthorization.class.getResourceAsStream( "/client_secrets.json" ) ) );

            httpClientTransport = GoogleNetHttpTransport.newTrustedTransport();

            flow = new GoogleAuthorizationCodeFlow.Builder( httpClientTransport, JSON_FACTORY, clientSecrets, SCOPES ).build();
        }
        catch ( Exception e )
        {
            LOG.log( Level.SEVERE, "Initialization failed! ", e );
            flow = null;
        }
    }

    public String createAuthURL()
        throws Exception
    {
        return flow.newAuthorizationUrl().setState( "google_callback" ).setRedirectUri( redirectUrl ).build();
    }

    public Userinfo getUserInfoByAuthCode( String code )
    {
        try
        {
            final TokenResponse response = flow.newTokenRequest( code ).setRedirectUri( redirectUrl ).execute();

            final Credential credential = flow.createAndStoreCredential( response, null );

            final Oauth2 oauth2 =
                new Oauth2.Builder( httpClientTransport, JSON_FACTORY, credential ).setApplicationName( "Enonic-CMS/4.7.5" ).build();

            return oauth2.userinfo().get().execute();
        }
        catch ( IOException e )
        {
            LOG.severe( "cannot get token: " + e.getMessage() );
            return null;
        }
    }

    public void setRedirectUrl( final String redirectUrl )
    {
        this.redirectUrl = redirectUrl;
    }
}
