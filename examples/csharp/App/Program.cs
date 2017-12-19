using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;

namespace App
{
    class Program
    {
        // Replace this with the actual issuer ID you've got from Wallester
        private static string _issuer = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

        // Replace this with the actual audience ID you've got from Wallester
        private static string _audience = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

        // Replace this with actual Wallester API URL
        private static string _apiURL = "http://xxx.wallester.eu/v1/test/ping";

        private static string _subject = "api-request";

        public static void Main(string[] args)
        {
            var signingCredentials = ReadSigningCredentials("../../keys/example_private.pkcs12", "123456");
            var wallesterPublicKey = ReadPublicKey("../../keys/example_wallester_public.cer");

            var request = new PingRequest
            {
                Message = "ping"
            };
            var requestBody = JsonConvert.SerializeObject(request);

            var responseBody = DoRequest(requestBody, signingCredentials, wallesterPublicKey);

            var response = JsonConvert.DeserializeObject<PingResponse>(responseBody);
            if (response.Message != "pong")
            {
                throw new ApplicationException("Invalid response message, expected 'pong', got '" + response.Message + "'");
            }

            Console.ReadKey();
        }

        // Reads signing credentials from a certificate file
        private static SigningCredentials ReadSigningCredentials(string filename, string password)
        {
            var cert = new X509Certificate2(filename, password);
            var key = new X509SecurityKey(cert);
            return new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        }

        // Reads public key from a PEM certificate
        private static SecurityKey ReadPublicKey(string filename)
        {
            SecurityKey key;

            using (var f = new FileStream(filename, FileMode.Open, FileAccess.Read))
            {
                var size = (int)f.Length;
                var rawData = new byte[size];
                size = f.Read(rawData, 0, size);

                var cert = new X509Certificate2(rawData);
                key = new X509SecurityKey(cert);
            }

            return key;
        }

        private static string DoRequest(string requestBody, SigningCredentials signingCredentials, SecurityKey wallesterPublicKey)
        {
            var requestBodyHash = CalculateRequestBodyHash(requestBody);
            var token = CreateToken(requestBodyHash, signingCredentials);

            Console.WriteLine("Request JWT token: " + token);

            string responseString;

            using (var client = new WebClient())
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/json";
                client.Headers[HttpRequestHeader.Authorization] = "Bearer " + token;
                responseString = client.UploadString(_apiURL, "POST", requestBody);
                var bearer = client.ResponseHeaders[HttpRequestHeader.Authorization];
                var responseToken = bearer.Replace("Bearer ", "");

                Console.WriteLine("Response JWT token: " + responseToken);

                var responseBodyHash = CalculateRequestBodyHash(responseString);

                try
                {
                    VerifyToken(responseToken, responseBodyHash, wallesterPublicKey);
                    Console.WriteLine("Response is trusted");
                }
                catch (Exception e)
                {
                    Console.WriteLine("Response is not trusted: " + e);
                }
            }

            return responseString;
        }

        private static void VerifyToken(String token, String responseBodyHash, SecurityKey wallesterPublicKey)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidAudience = _issuer,
                ValidateAudience = true,
                ValidIssuer = _audience,
                ValidateIssuer = true,
                ValidateLifetime = true,
                IssuerSigningKey = wallesterPublicKey,
                ValidateIssuerSigningKey = true
            };

            SecurityToken validatedToken;
            var handler = new JwtSecurityTokenHandler();
            var claimsPrincipal = handler.ValidateToken(token, tokenValidationParameters, out validatedToken);

            var rbh = claimsPrincipal.FindFirst("rbh");
            if (rbh == null)
            {
                throw new ApplicationException("missing response body hash");
            }

            if (rbh.Value != responseBodyHash)
            {
                throw new ApplicationException("invalid response body hash: " + rbh.Value);
            }

            var jwtToken = new JwtSecurityToken(token);
            if (jwtToken.Subject != _subject)
            {
                throw new ApplicationException("invalid subject: " + jwtToken.Subject);
            }
        }

        private static string CalculateRequestBodyHash(string body)
        {
            var bytes = Encoding.UTF8.GetBytes(body);
            var hash = new SHA256Managed().ComputeHash(bytes);
            return Convert.ToBase64String(hash);
        }

        private static string CreateToken(string requestBodyHash, SigningCredentials signingCredentials)
        {
            Claim[] claims = {
                new Claim("sub", _subject),
                new Claim("rbh", requestBodyHash)
            };

            var notBefore = DateTime.UtcNow;
            var expires = DateTime.UtcNow.AddMinutes(1);
            var token = new JwtSecurityToken(_issuer, _audience, claims, notBefore, expires, signingCredentials);

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }
    }
}
