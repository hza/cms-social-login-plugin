package com.enonic.cms.plugin.google.login;

import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.services.oauth2.model.Userinfo;

import com.enonic.cms.api.client.ClientException;
import com.enonic.cms.api.client.ClientFactory;
import com.enonic.cms.api.client.LocalClient;
import com.enonic.cms.api.client.model.CreateUserParams;
import com.enonic.cms.api.client.model.GetUserParams;
import com.enonic.cms.api.client.model.JoinGroupsParams;
import com.enonic.cms.api.plugin.ext.http.HttpInterceptor;

public final class LoginPageInterceptor
    extends HttpInterceptor
{
    private static final Logger LOG = Logger.getLogger( "google-login-plugin" );

    private static final String REPOSITORY_NAME = "google";

    private GoogleAuthorization googleAuthorization = new GoogleAuthorization();

    /**
     * Executes before the actual resource being called.
     */
    public boolean preHandle( HttpServletRequest request, HttpServletResponse response )
    {

        final boolean alreadyWrapped = response instanceof LoginPageProcessor;

        if ( !alreadyWrapped )
        {
            try
            {
                String errorMessage = null;

                if ( ( REPOSITORY_NAME + "_callback" ).equals( request.getParameter( "state" ) ) )
                {
                    final String code = request.getParameter( "code" );

                    if ( code == null )
                    {
                        errorMessage = "Authorization with Google failed";
                    }
                }

                googleAuthorization.setRedirectUrl( request.getRequestURL().toString() );

                final LoginPageProcessor loginPageHTMLInjector =
                    new LoginPageProcessor( REPOSITORY_NAME, response, googleAuthorization.createAuthURL(), errorMessage );

                request.getRequestDispatcher( "/admin/login" ).forward( request, loginPageHTMLInjector );
            }
            catch ( Exception e )
            {
                LOG.severe( e.getMessage() );
            }

            return false;
        }
        else
        {
            // callback from google
            if ( ( REPOSITORY_NAME + "_callback" ).equals( request.getParameter( "state" ) ) && "GET".equals( request.getMethod() ) )
            {
                final String code = request.getParameter( "code" );

                if ( code != null )
                {
                    final Userinfo userInfo = googleAuthorization.getUserInfoByAuthCode( code );

                    if ( userInfo != null )
                    {
                        createUserIfNotExists( userInfo );
                        loginToAdmin( request, response, userInfo );
                    }
                }
            }
        }

        return true;
    }

    private void createUserIfNotExists( final Userinfo userInfo )
    {
        final LocalClient client = ClientFactory.getLocalClient();

        client.login( "admin", "password" );

        if ( !userExists( userInfo, client ) )
        {
            createNewUser( userInfo, client );
        }

        client.logout( true );
    }

    private boolean userExists( final Userinfo userInfo, final LocalClient client )
    {
        try
        {
            final GetUserParams getUserParams = new GetUserParams();
            getUserParams.user = REPOSITORY_NAME + ":" + userInfo.getEmail();
            client.getUser( getUserParams );
            return true;
        }
        catch ( ClientException e )
        {
            LOG.info( "User exists API call failed: " + e.getMessage() );
            return false;
        }
    }

    private void createNewUser( final Userinfo userInfo, final LocalClient client )
    {
        final CreateUserParams createUserParams = new CreateUserParams();
        createUserParams.userstore = REPOSITORY_NAME;
        createUserParams.username = userInfo.getEmail();
        createUserParams.password = userInfo.getId();
        createUserParams.email = userInfo.getEmail();
        createUserParams.displayName = userInfo.getName();
        client.createUser( createUserParams );

        final JoinGroupsParams joinGroupsParams = new JoinGroupsParams();
        joinGroupsParams.user = REPOSITORY_NAME + ":" + userInfo.getEmail();
        joinGroupsParams.groupsToJoin = new String[]{"Administrators"};
        client.joinGroups( joinGroupsParams );
    }

    private void loginToAdmin( final HttpServletRequest request, final HttpServletResponse response, final Userinfo userInfo )
    {
        final Map<Object, Object> parameterMap = request.getParameterMap();

        parameterMap.put( "username", userInfo.getEmail() );
        parameterMap.put( "password", userInfo.getId() );
        parameterMap.put( "userstorekey", LoginPageProcessor.getUserstoreId() );
        parameterMap.put( "login", "true" );
    }

    /**
     * Executes after the actual resource being called.
     */
    public void postHandle( HttpServletRequest request, HttpServletResponse response )
    {
        // none
    }
}
