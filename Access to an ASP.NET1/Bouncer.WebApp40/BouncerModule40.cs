//-----------------------------------------------------------------------
// <copyright file="BouncerModule40.cs" company="Microsoft Corporation">
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//        you may not use this file except in compliance with the License.
//        You may obtain a copy of the License at
//            http://www.apache.org/licenses/LICENSE-2.0
//        Unless required by applicable law or agreed to in writing, software
//        distributed under the License is distributed on an "AS IS" BASIS,
//       WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//        See the License for the specific language governing permissions and
//        limitations under the License.
// </copyright>
//-----------------------------------------------------------------------
namespace Bouncer.WebApp40
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Configuration;
    using System.IdentityModel.Tokens;
    using System.IO;
    using System.Linq;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Web;
    using System.Web.Configuration;
    using System.Xml;
    using Bouncer.Configuration;
    using Microsoft.IdentityModel.Claims;
    using Microsoft.IdentityModel.Configuration;
    using Microsoft.IdentityModel.Protocols.WSFederation;
    using Microsoft.IdentityModel.Protocols.WSTrust;
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.IdentityModel.Web;
    using Microsoft.IdentityModel.Web.Configuration;

    /// <summary>
    /// Enables a website to be secured using federation with multiple external Identity Providers
    /// </summary>
    public class BouncerModule40 : IHttpModule
    {
        /// <summary>
        /// Disposes of the resources (other than memory) used by the module that implements <see cref="T:System.Web.IHttpModule"/>.
        /// </summary>
        public void Dispose()
        {
        }

        /// <summary>
        /// Initializes a module and prepares it to handle requests.
        /// </summary>
        /// <param name="context">An <see cref="T:System.Web.HttpApplication"/> that provides access to the methods, properties, and events common to all application objects within an ASP.NET application</param>
        public void Init(HttpApplication context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            context.BeginRequest += this.OnBeginRequest;
        }

        /// <summary>
        /// Called when [begin request].
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="e">The <see cref="System.EventArgs"/> instance containing the event data.</param>
        public void OnBeginRequest(object source, EventArgs e)
        {
            // Get the call chain from the cookie (or from config in the absence of a cookie)
            Queue<string> callChain = DeserializeCallChainCookie(HttpContext.Current.Request.Cookies);

            // Dequeue an IDP
            if (callChain != null &&
                callChain.Count > 0)
            {
                string currentIdp = callChain.Dequeue();

                ServiceConfiguration serviceConfig = GetServiceConfiguration(currentIdp);

                try
                {
                    SessionAuthenticationModule sessionMod = CreateSessionModule(serviceConfig);

                    // Initially assume the custom session cookie is present
                    if (sessionMod.ContainsSessionTokenCookie(HttpContext.Current.Request.Cookies))
                    {
                        ValidateSessionSecurityToken(sessionMod, serviceConfig);

                        // All is well, serialise the call chain
                        SerializeCallChainCookie(callChain);
                    }
                    else
                    {
                        // Assume this is a signin response (an error will occur if not, resulting in a browser redirect to the current Identity Provider)
                        WSFederationAuthenticationModule mod = CreateFederationModule(currentIdp);

                        SignInResponseMessage signinResponse = mod.GetSignInResponseMessage(HttpContext.Current.Request);

                        WSFederationSerializer serializer = null;

                        using (XmlDictionaryReader xmlDictionaryReader = XmlDictionaryReader.CreateTextReader(
                            Encoding.UTF8.GetBytes(signinResponse.Result),
                            new XmlDictionaryReaderQuotas
                            {
                                MaxArrayLength = 2097152,
                                MaxStringContentLength = 2097152
                            }))
                        {
                            serializer = new WSFederationSerializer(xmlDictionaryReader);
                        }

                        WSTrustSerializationContext context = new WSTrustSerializationContext(serviceConfig.SecurityTokenHandlerCollectionManager);
                        RequestSecurityTokenResponse requestSecurityTokenResponse = serializer.CreateResponse(signinResponse, context);
                        string receivedTokenXml = requestSecurityTokenResponse.RequestedSecurityToken.SecurityTokenXml.OuterXml;
                        ValidateSignInResponse(receivedTokenXml, serviceConfig);

                        // All is well, set this IDP to complete and queue the next one
                        SerializeCallChainCookie(callChain);

                        HttpContext.Current.Response.Redirect(GetReturnUrl(signinResponse.Context), false);
                        HttpContext.Current.ApplicationInstance.CompleteRequest();
                        return;
                    }
                }
                catch (WSFederationMessageException)
                {
                    if (!System.Threading.Thread.CurrentPrincipal.Identity.IsAuthenticated)
                    {
                        WSFederationAuthenticationModule mod = CreateFederationModule(currentIdp);

                        mod.RedirectToIdentityProvider(Guid.NewGuid().ToString(), HttpContext.Current.Request.Url.OriginalString, true);
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    HttpContext.Current.Response.Redirect("AccessDenied.aspx");
                }
            }
            else
            {
                // All IdP's have been negotiated. Remove any cookies associated with the bespoke authentications
                foreach (var idp in ((IdentityProvidersToCallSection)WebConfigurationManager.GetSection("identityProvidersToCall")).GetOrderedIdentityProvidersCallChain())
                {
                    HttpContext.Current.Response.Cookies.Add(new HttpCookie(idp) { Expires = DateTime.UtcNow.AddDays(-1) });
                    HttpContext.Current.Response.Cookies.Add(new HttpCookie(string.Concat(idp, "1")) { Expires = DateTime.UtcNow.AddDays(-1) });
                }
            }
        }

        /// <summary>
        /// Serializes the call chain cookie.
        /// </summary>
        /// <param name="callChain">The call chain.</param>
        private static void SerializeCallChainCookie(Queue<string> callChain)
        {
            // Convert the call chain to a byte array
            BinaryFormatter ser = new BinaryFormatter();
            byte[] callChainBytes;

            using (MemoryStream ms = new MemoryStream())
            {
                ser.Serialize(ms, callChain);

                ms.Seek(0, SeekOrigin.Begin);

                callChainBytes = new byte[ms.Length];

                ms.Read(callChainBytes, 0, (int)ms.Length);
            }

            // Convert the bytes to a string
            string callChainAsString = System.Convert.ToBase64String(callChainBytes);

            // Encrypt the bytes
            byte[] encryptedBytes = null;

            using (AesManaged aesProvider = new AesManaged()
            {
                Key = System.Convert.FromBase64String(ConfigurationManager.AppSettings["SharedSecretKey"]),
                IV = System.Convert.FromBase64String(ConfigurationManager.AppSettings["SharedSecretIV"])
            })
            {
                ICryptoTransform encryptor = aesProvider.CreateEncryptor(aesProvider.Key, aesProvider.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream encryptStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter encryptStreamWriter = new StreamWriter(encryptStream))
                        {
                            encryptStreamWriter.Write(callChainAsString);
                        }

                        encryptedBytes = memoryStream.ToArray();
                    }
                }
            }

            // Finally, serialize the cookie
            HttpContext.Current.Response.Cookies.Add(new HttpCookie("callChainCookie", System.Convert.ToBase64String(encryptedBytes)));
        }

        /// <summary>
        /// Deserializes the call chain cookie.
        /// </summary>
        /// <param name="requestCookies">The request cookies.</param>
        /// <returns>The call chain.</returns>
        private static Queue<string> DeserializeCallChainCookie(HttpCookieCollection requestCookies)
        {
            // Retrieve the cookie describing where in the call chain we are
            var callChainCookie = (from cookie in requestCookies.Cast<string>()
                                   where cookie == "callChainCookie"
                                   select requestCookies[cookie]).FirstOrDefault();

            if (callChainCookie == null)
            {
                // Return the identity providers call chain ordered by sequence number
                return ((IdentityProvidersToCallSection)WebConfigurationManager.GetSection("identityProvidersToCall")).GetOrderedIdentityProvidersCallChain();
            }
            else
            {
                // First retrieve the contents of the cookie
                byte[] callChainBytes = System.Convert.FromBase64String(callChainCookie.Value);

                // Decrypt the bytes
                string plainText = string.Empty;

                using (AesManaged aesProvider = new AesManaged()
                {
                    Key = System.Convert.FromBase64String(ConfigurationManager.AppSettings["SharedSecretKey"]),
                    IV = System.Convert.FromBase64String(ConfigurationManager.AppSettings["SharedSecretIV"])
                })
                {
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesProvider.CreateDecryptor(aesProvider.Key, aesProvider.IV);

                    // Create the streams used for decryption. 
                    using (MemoryStream memoryStream = new MemoryStream(callChainBytes))
                    {
                        using (CryptoStream decryptStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader decryptStreamWriter = new StreamReader(decryptStream))
                            {
                                // Read the decrypted bytes from the decrypting stream 
                                // and place them in a string.
                                plainText = decryptStreamWriter.ReadToEnd();
                            }
                        }
                    }
                }

                // Finally, deserialise the call chain
                byte[] decryptedBytes = System.Convert.FromBase64String(plainText);
                BinaryFormatter ser = new BinaryFormatter();
                
                using (MemoryStream ms2 = new MemoryStream())
                {
                    ms2.Write(decryptedBytes, 0, decryptedBytes.Length);

                    ms2.Seek(0, SeekOrigin.Begin);

                    return (Queue<string>)ser.Deserialize(ms2);
                }
            }
        }

        /// <summary>
        /// Gets the return URL.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <returns>The return url.</returns>
        /// <exception cref="System.InvalidOperationException">Could not locate return URL in context</exception>
        private static string GetReturnUrl(string context)
        {
            NameValueCollection nameValueCollection = HttpUtility.ParseQueryString(context);
            foreach (string text in nameValueCollection.Keys)
            {
                if (text == "ru")
                {
                    return nameValueCollection[text];
                }
            }

            throw new InvalidOperationException("Could not locate return URL in context");
        }

        /// <summary>
        /// Creates a federation module.
        /// </summary>
        /// <param name="currentIdentityProviderName">Name of the current identity provider.</param>
        /// <returns>A WSFederationAuthenticationModule instance.</returns>
        private static WSFederationAuthenticationModule CreateFederationModule(string currentIdentityProviderName)
        {
            ServiceElement element = MicrosoftIdentityModelSection.Current.ServiceElements.GetElement(currentIdentityProviderName);

            if (element != null)
            {
                WSFederationAuthenticationElement federationElement = element.FederatedAuthentication.WSFederation;

                return new WSFederationAuthenticationModule
                {
                    Issuer = federationElement.Issuer,
                    RequireHttps = federationElement.RequireHttps,
                    Freshness = federationElement.Freshness,
                    AuthenticationType = federationElement.AuthenticationType,
                    HomeRealm = federationElement.HomeRealm,
                    Policy = federationElement.Policy,
                    Realm = federationElement.Realm,
                    Reply = federationElement.Reply,
                    SignOutReply = federationElement.SignOutReply,
                    Request = federationElement.Request,
                    RequestPtr = federationElement.RequestPtr,
                    Resource = federationElement.Resource,
                    SignInQueryString = federationElement.SignInQueryString,
                    SignOutQueryString = federationElement.SignOutQueryString,
                    PassiveRedirectEnabled = federationElement.PassiveRedirectEnabled,
                    PersistentCookiesOnPassiveRedirects = federationElement.PersistentCookiesOnPassiveRedirects
                };
            }

            throw new InvalidOperationException("Cannot locate a WIF element with service element name set to " + currentIdentityProviderName);
        }

        /// <summary>
        /// Validates the sign in response.
        /// </summary>
        /// <param name="receivedTokenXml">The received token XML.</param>
        /// <param name="serviceConfig">The service config.</param>
        private static void ValidateSignInResponse(string receivedTokenXml, ServiceConfiguration serviceConfig)
        {
            SecurityToken receivedToken = null;

            using (XmlDictionaryReader xmlDictionaryReader = XmlDictionaryReader.CreateTextReader(
            Encoding.UTF8.GetBytes(receivedTokenXml),
            new XmlDictionaryReaderQuotas
            {
                MaxArrayLength = 2097152,
                MaxStringContentLength = 2097152
            }))
            {
                receivedToken = serviceConfig.SecurityTokenHandlers.ReadToken(xmlDictionaryReader);
            }

            var identity = serviceConfig.SecurityTokenHandlers.ValidateToken(receivedToken);

            ClaimsPrincipal prin = new ClaimsPrincipal(identity);

            SessionSecurityToken sessTok = new SessionSecurityToken(prin);

            CreateSessionModule(serviceConfig).WriteSessionTokenToCookie(sessTok);
        }

        /// <summary>
        /// Validates the session security token.
        /// </summary>
        /// <param name="sessionMod">The session mod.</param>
        /// <param name="serviceConfig">The service config.</param>
        private static void ValidateSessionSecurityToken(SessionAuthenticationModule sessionMod, ServiceConfiguration serviceConfig)
        {
            // Deserialize the cookie
            SessionSecurityToken sessiontok = null;

            if (sessionMod.TryReadSessionTokenFromCookie(out sessiontok))
            {
                if (sessiontok != null)
                {
                    // Validate the session token
                    serviceConfig.SecurityTokenHandlers.ValidateToken(sessiontok);
                }
                else
                {
                    throw new UnauthorizedAccessException("The session security token resulting from cookie deserialization is null");
                }
            }
            else
            {
                throw new UnauthorizedAccessException("The Session cookie is present but a session security token could not be read from it");
            }
        }

        /// <summary>
        /// Gets the service configuration.
        /// </summary>
        /// <param name="identityProviderName">Name of the identity provider.</param>
        /// <returns>
        /// A ServiceConfiguration instance
        /// </returns>
        private static ServiceConfiguration GetServiceConfiguration(string identityProviderName)
        {
            ServiceConfiguration serviceConfig = new ServiceConfiguration(identityProviderName);

            var cookieProtectionCertificate = GetCertificate();

            // Plug in the web farm enabled session security token handler
            serviceConfig.SecurityTokenHandlers.AddOrReplace(new SessionSecurityTokenHandler(new System.Collections.ObjectModel.ReadOnlyCollection<CookieTransform>(
                    new List<CookieTransform> 
                    { 
                        new DeflateCookieTransform(), 
                        new RsaEncryptionCookieTransform(cookieProtectionCertificate), 
                        new RsaSignatureCookieTransform(cookieProtectionCertificate) 
                    })));

            return serviceConfig;
        }

        /// <summary>
        /// Gets the certificate.
        /// </summary>
        /// <returns>A X509Certificate2 instance</returns>
        private static X509Certificate2 GetCertificate()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                store.Open(OpenFlags.ReadOnly);

                if (store.Certificates != null)
                {
                    X509Certificate2Collection certColl = store.Certificates.Find(X509FindType.FindByThumbprint, ConfigurationManager.AppSettings["SecretCertificateThumbprint"], false);

                    if (certColl != null &&
                        certColl.Count > 0)
                    {
                        return certColl[0];
                    }
                }

                throw new CryptographicException("Could not locate cert");
            }
            finally
            {
                if (store != null)
                {
                    store.Close();
                }
            }
        }

        /// <summary>
        /// Creates the session module.
        /// </summary>
        /// <param name="config">The config.</param>
        /// <returns>A SessionAuthenticationModule instance</returns>
        private static SessionAuthenticationModule CreateSessionModule(ServiceConfiguration config)
        {
            SessionAuthenticationModule sessionMod = new SessionAuthenticationModule();
            sessionMod.ServiceConfiguration = config;
            ChunkedCookieHandler chunkedCookieHandler = new ChunkedCookieHandler();
            chunkedCookieHandler.Name = config.Name;
            sessionMod.CookieHandler = chunkedCookieHandler;

            return sessionMod;
        }
    }
}
