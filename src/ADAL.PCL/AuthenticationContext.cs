//----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//----------------------------------------------------------------------

using System;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Clients.ActiveDirectory
{
    internal enum AuthorityValidationType
    {
        True,
        False,
        NotProvided
    }

    /// <summary>
    /// The AuthenticationContext class retrieves authentication tokens from Azure Active Directory and ADFS services.
    /// </summary>
    public sealed class AuthenticationContext
    {
        internal Authenticator Authenticator;

        static AuthenticationContext()
        {
            PlatformPlugin.Logger.Information(null, string.Format("ADAL {0} with assembly version '{1}', file version '{2}' and informational version '{3}' is running...",
                PlatformPlugin.PlatformInformation.GetProductName(), AdalIdHelper.GetAdalVersion(), AdalIdHelper.GetAssemblyFileVersion(), AdalIdHelper.GetAssemblyInformationalVersion()));
        }

        /// <summary>
        /// Constructor to create the context with the address of the authority.
        /// Using this constructor will turn ON validation of the authority URL by default if validation is supported for the authority address.
        /// </summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        public AuthenticationContext(string authority)
            : this(authority, AuthorityValidationType.NotProvided, TokenCache.DefaultShared)
        {
        }

        /// <summary>
        /// Constructor to create the context with the address of the authority and flag to turn address validation off.
        /// Using this constructor, address validation can be turned off. Make sure you are aware of the security implication of not validating the address.
        /// </summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="validateAuthority">Flag to turn address validation ON or OFF.</param>
        public AuthenticationContext(string authority, bool validateAuthority)
            : this(authority, validateAuthority ? AuthorityValidationType.True : AuthorityValidationType.False, TokenCache.DefaultShared)
        {
        }

        /// <summary>
        /// Constructor to create the context with the address of the authority.
        /// Using this constructor will turn ON validation of the authority URL by default if validation is supported for the authority address.
        /// </summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="tokenCache">Token cache used to lookup cached tokens on calls to AcquireToken</param>
        public AuthenticationContext(string authority, TokenCache tokenCache)
            : this(authority, AuthorityValidationType.NotProvided, tokenCache)
        {
        }

        /// <summary>
        /// Constructor to create the context with the address of the authority and flag to turn address validation off.
        /// Using this constructor, address validation can be turned off. Make sure you are aware of the security implication of not validating the address.
        /// </summary>
        /// <param name="authority">Address of the authority to issue token.</param>
        /// <param name="validateAuthority">Flag to turn address validation ON or OFF.</param>
        /// <param name="tokenCache">Token cache used to lookup cached tokens on calls to AcquireToken</param>
        public AuthenticationContext(string authority, bool validateAuthority, TokenCache tokenCache)
            : this(authority, validateAuthority ? AuthorityValidationType.True : AuthorityValidationType.False, tokenCache)
        {
        }

        private AuthenticationContext(string authority, AuthorityValidationType validateAuthority, TokenCache tokenCache)
        {
            // If authorityType is not provided (via first constructor), we validate by default (except for ASG and Office tenants).
            this.Authenticator = new Authenticator(authority, (validateAuthority != AuthorityValidationType.False));

            this.TokenCache = tokenCache;
        }

        /// <summary>
        /// Gets address of the authority to issue token.
        /// </summary>
        public string Authority
        {
            get
            {
                return this.Authenticator.Authority;
            }
        }

        /// <summary>
        /// Gets a value indicating whether address validation is ON or OFF.
        /// </summary>
        public bool ValidateAuthority
        {
            get
            {
                return this.Authenticator.ValidateAuthority;
            }
        }

        /// <summary>
        /// Property to provide ADAL's token cache. Depending on the platform, TokenCache may have a default persistent cache or not. 
        /// Library will automatically save tokens in default TokenCache whenever you obtain them. Cached tokens will be available only to the application that saved them. 
        /// If the cache is persistent, the tokens stored in it will outlive the application's execution, and will be available in subsequent runs.
        /// To turn OFF token caching, set TokenCache to null. 
        /// </summary>
        public TokenCache TokenCache { get; private set; }

        /// <summary>
        /// Gets or sets correlation Id which would be sent to the service with the next request. 
        /// Correlation Id is to be used for diagnostics purposes. 
        /// </summary>
        public Guid CorrelationId
        {
            get
            {
                return this.Authenticator.CorrelationId;
            }

            set
            {
                this.Authenticator.CorrelationId = value;                
            }
        }

        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, string clientId)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientId), null);
        }

        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, string clientId, string []scopes)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientId), scopes);
        }

        /// <summary>
        /// Acquires security token from the authority using authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string, string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientCredential), null);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string, string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="clientCredential">The credential to use for token acquisition.</param>
        /// <param name="scopes">...</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientCredential clientCredential, string []scopes)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientCredential), scopes);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string[], string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientAssertion), null);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string[], string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="scopes">...</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertion clientAssertion, string []scopes)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientAssertion), scopes);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string[], string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertionCertificate clientCertificate)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientCertificate, this.Authenticator), null);
        }

        /// <summary>
        /// Acquires security token from the authority using an authorization code previously received.
        /// This method does not lookup token cache, but stores the result in it, so it can be looked up using other methods such as <see cref="AuthenticationContext.AcquireTokenSilentAsync(string[], string, UserIdentifier)"/>.
        /// </summary>
        /// <param name="authorizationCode">The authorization code received from service authorization endpoint.</param>
        /// <param name="redirectUri">The redirect address used for obtaining authorization code.</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="scopes">...</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeAsync(string authorizationCode, Uri redirectUri, ClientAssertionCertificate clientCertificate, string []scopes)
        {
            return await this.AcquireTokenByAuthorizationCodeCommonAsync(authorizationCode, redirectUri, new ClientKey(clientCertificate, this.Authenticator), scopes);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string []scopes, ClientCredential clientCredential, UserAssertion userAssertion)
        {
            return await this.AcquireTokenOnBehalfCommonAsync(scopes, new ClientKey(clientCredential), userAssertion);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string []scopes, ClientAssertionCertificate clientCertificate, UserAssertion userAssertion)
        {
            return await this.AcquireTokenOnBehalfCommonAsync(scopes, new ClientKey(clientCertificate, this.Authenticator), userAssertion);
        }

        /// <summary>
        /// Acquires an access token from the authority on behalf of a user. It requires using a user token previously received.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userAssertion">The user assertion (token) to use for token acquisition.</param>
        /// <returns>It contains Access Token and the Access Token's expiration time.</returns>
        public async Task<AuthenticationResult> AcquireTokenAsync(string []scopes, ClientAssertion clientAssertion, UserAssertion userAssertion)
        {
            return await this.AcquireTokenOnBehalfCommonAsync(scopes, new ClientKey(clientAssertion), userAssertion);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string []scopes, string clientId)
        {
            return await this.AcquireTokenSilentCommonAsync(scopes, new ClientKey(clientId), UserIdentifier.AnyUser);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="UserIdentifier"/>.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string []scopes, string clientId, UserIdentifier userId)
        {
            return await this.AcquireTokenSilentCommonAsync(scopes, new ClientKey(clientId), userId);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientCredential">The client credential to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="UserIdentifier"/>.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string []scopes, ClientCredential clientCredential, UserIdentifier userId)
        {
            return await this.AcquireTokenSilentCommonAsync(scopes, new ClientKey(clientCredential), userId);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientCertificate">The client certificate to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="UserIdentifier"/>.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string []scopes, ClientAssertionCertificate clientCertificate, UserIdentifier userId)
        {
            return await this.AcquireTokenSilentCommonAsync(scopes, new ClientKey(clientCertificate, this.Authenticator), userId);
        }

        /// <summary>
        /// Acquires security token without asking for user credential.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientAssertion">The client assertion to use for token acquisition.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="UserIdentifier"/>.Any.</param>
        /// <returns>It contains Access Token, Refresh Token and the Access Token's expiration time. If acquiring token without user credential is not possible, the method throws AdalException.</returns>
        public async Task<AuthenticationResult> AcquireTokenSilentAsync(string []scopes, ClientAssertion clientAssertion, UserIdentifier userId)
        {
            return await this.AcquireTokenSilentCommonAsync(scopes, new ClientKey(clientAssertion), userId);
        }

        /// <summary>
        /// Gets URL of the authorize endpoint including the query parameters.
        /// </summary>
        /// <param name="scopes">...</param>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="redirectUri">Address to return to upon receiving a response from the authority.</param>
        /// <param name="userId">Identifier of the user token is requested for. This parameter can be <see cref="UserIdentifier"/>.Any.</param>
        /// <param name="extraQueryParameters">This parameter will be appended as is to the query string in the HTTP authentication request to the authority. The parameter can be null.</param>
        /// <returns>URL of the authorize endpoint including the query parameters.</returns>
        public async Task<Uri> GetAuthorizationRequestUrlAsync(string []scopes, string clientId, Uri redirectUri, UserIdentifier userId, string extraQueryParameters)
        {
            var handler = new AcquireTokenInteractiveHandler(this.Authenticator, this.TokenCache, scopes[0], clientId, redirectUri, null, userId, extraQueryParameters, null);
            return await handler.CreateAuthorizationUriAsync(this.CorrelationId);
        }

        public async Task<string> AcquireUserAuthorizationAsync(string []scopes, string clientId, Uri redirectUri, IPlatformParameters parameters)
        {
            return await this.AcquireTokenCommonAsync(scopes, clientId, redirectUri, parameters, UserIdentifier.AnyUser);
        }

        public async Task<string> AcquireUserAuthorizationAsync(string []scopes, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId)
        {
            return await this.AcquireTokenCommonAsync(scopes, clientId, redirectUri, parameters, userId);
        }

        public async Task<string> AcquireUserAuthorizationAsync(string []scopes, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId, string extraQueryParameters)
        {
            return await this.AcquireTokenCommonAsync(scopes, clientId, redirectUri, parameters, userId, extraQueryParameters);
        }

        private async Task<AuthenticationResult> AcquireTokenByAuthorizationCodeCommonAsync(string authorizationCode, Uri redirectUri, ClientKey clientKey, string []scopes)
        {
            var handler = new AcquireTokenByAuthorizationCodeHandler(this.Authenticator, this.TokenCache, scopes != null ? scopes[0] : null, clientKey, authorizationCode, redirectUri);
            return await handler.RunAsync();
        }

        private async Task<AuthenticationResult> AcquireTokenOnBehalfCommonAsync(string []scopes, ClientKey clientKey, UserAssertion userAssertion)
        {
            var handler = new AcquireTokenOnBehalfHandler(this.Authenticator, this.TokenCache, scopes[0], clientKey, userAssertion);
            return await handler.RunAsync();
        }

        internal IWebUI CreateWebAuthenticationDialog(IPlatformParameters parameters)
        {
            return PlatformPlugin.WebUIFactory.CreateAuthenticationDialog(parameters);
        }

        private async Task<string> AcquireTokenCommonAsync(string []scopes, string clientId, Uri redirectUri, IPlatformParameters parameters, UserIdentifier userId, string extraQueryParameters = null)
        {
            var handler = new AcquireTokenInteractiveHandler(this.Authenticator, this.TokenCache, scopes[0], clientId, redirectUri, parameters, userId, extraQueryParameters, this.CreateWebAuthenticationDialog(parameters));
            var result = await handler.RunAsync();
            return result.AccessToken;  // This is actually authorization code.
        }

        private async Task<AuthenticationResult> AcquireTokenSilentCommonAsync(string []scopes, ClientKey clientKey, UserIdentifier userId)
        {
            var handler = new AcquireTokenSilentHandler(this.Authenticator, this.TokenCache, scopes[0], clientKey, userId);
            return await handler.RunAsync();
        }
    }
}
