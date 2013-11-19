package com.enonic.cms.plugin.google.login;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

final class LoginPageProcessor
    extends HttpServletResponseWrapper
{
    private boolean isWritten = false;

    private String repositoryName;

    private String authURL;

    private String errorMessage;

    private static String userstoreId = null;

    public LoginPageProcessor( final String repositoryName, final HttpServletResponse response, final String authURL,
                               final String errorMessage )
    {
        super( response );

        this.repositoryName = repositoryName;
        this.authURL = authURL;
        this.errorMessage = errorMessage;

    }

    public PrintWriter getWriter()
        throws IOException
    {
        return new PrintWriter( super.getWriter() )
        {
            private StringBuilder selectCodeBuilder = null;

            public void write( String s )
            {
                injectSocialLoginLink( s );
                dumpErrorMessage( s );
                resolveUserstoreId( s );

                super.write( s );
            }

            // It is better to have comment like <!-- placeholder for links -->
            private void injectSocialLoginLink( final String s )
            {
                if ( !isWritten && "h1".equals( s ) )
                {
                    isWritten = true;

                    super.write( "a href=\"" + authURL +
                                     "\" style=\"position:absolute; color: white; margin: 6px; text-decoration: underline\">Log in using Google account</a> <" );
                }
            }

            // dump error message that is received from google
            private void dumpErrorMessage( final String s )
            {
                if ( errorMessage != null && "Empty".equals( s ) )
                {
                    super.write( "-->" );
                    super.write( errorMessage );
                    super.write( "<!--" );
                }
            }

            // Client API does not have possibility to get to know id of userstore, so it is done here
            private void resolveUserstoreId( final String s )
            {
                if ( selectCodeBuilder != null )
                {
                    selectCodeBuilder.append( s );
                    selectCodeBuilder.append( " " );
                }

                if ( "select".equals( s ) )
                {
                    if ( selectCodeBuilder != null ) // last select
                    {
                        final String options = selectCodeBuilder.toString();

                        final Pattern pattern = Pattern.compile( ".*(\\d+).*" + repositoryName + ".*" );
                        final Matcher matcher = pattern.matcher( options );

                        if ( matcher.matches() )
                        {
                            userstoreId = matcher.group( 1 );
                        }

                        selectCodeBuilder = null;
                    }
                    else
                    {
                        selectCodeBuilder = new StringBuilder();
                    }
                }
            }
        };
    }

    public static String getUserstoreId()
    {
        return userstoreId;
    }
}
