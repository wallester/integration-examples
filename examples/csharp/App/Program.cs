﻿// #define READ_KEYS_FROM_STRINGS
// #define UPLOAD_KYC_DOCUMENTS // Uncomment this line to send upload kyc documents request

using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
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
        private const string Issuer = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";

        // Replace this with the actual audience ID you've got from Wallester
        private const string Audience = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX";

        // Replace this with actual Wallester API URL
        private const string ApiUrl = "https://xxx.wallester.eu";
        private const string PingPath = "/v1/test/ping";
        private const string UploadKycDocumentPath = "/v1/kyc-documents";

        private const string Subject = "api-request";

        // Replace this with actual data to send upload kyc documents request
        private const string AuditSourceType = "Backend";
        private const string AuditUserId = "integration-example";
        private const string ProductCode = "PRODUCTCODE";
        private const string KycCheckId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
        private const string FilePath = "../../testdata/file_name.jpg";

        #if READ_KEYS_FROM_STRINGS
            // Replace this with actual private key
            private const string PrivateKeyPem = """
            -----BEGIN RSA PRIVATE KEY-----
            ...
            ...
            ...
            -----END RSA PRIVATE KEY-----
            """;

            // Replace this with actual public key
            private const string PublicKeyPem = """
            -----BEGIN PUBLIC KEY-----
            ...
            ...
            ...
            -----END PUBLIC KEY-----
            """;
        #endif

        public static void Main(string[] args)
        {
            SigningCredentials signingCredentials;
            SecurityKey wallesterPublicKey;
            #if READ_KEYS_FROM_STRINGS
                signingCredentials = ReadSigningCredentialsFromString(PrivateKeyPem);
                wallesterPublicKey = ReadPublicKeyFromString(PublicKeyPem);
            #else
                signingCredentials = ReadSigningCredentials("../../keys/example_private.pkcs12", "123456");
                wallesterPublicKey = ReadPublicKey("../../keys/example_wallester_public.cer");
            #endif

            var response = ExecuteRequest(signingCredentials);
            ValidateResponse(response, wallesterPublicKey);
            var responseBody = response.Content.ReadAsStringAsync().Result;

            Console.WriteLine("Response: " + responseBody);
        }

        private static SigningCredentials ReadSigningCredentialsFromString(string privateKeyPem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem.ToCharArray());

            var key = new RsaSecurityKey(rsa);
            return new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        }

        private static SecurityKey ReadPublicKeyFromString(string publicKeyPem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem.ToCharArray());

            return new RsaSecurityKey(rsa);
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

            using var f = new FileStream(filename, FileMode.Open, FileAccess.Read);
            {
                var size = (int)f.Length;
                var rawData = new byte[size];
                size = f.Read(rawData, 0, size);

                var cert = new X509Certificate2(rawData);
                key = new X509SecurityKey(cert);
            }

            return key;
        }

        private static HttpResponseMessage ExecuteRequest(SigningCredentials signingCredentials)
        {
            #if UPLOAD_KYC_DOCUMENTS
                return ExecuteUploadKycRequest(signingCredentials);
            #else
                return ExecutePingRequest(signingCredentials);
            #endif
        }

        private static HttpResponseMessage ExecuteUploadKycRequest(SigningCredentials signingCredentials)
        {
            if (!File.Exists(FilePath))
            {
                throw new FileNotFoundException("The file was not found", FilePath);
            }

            var fileBytes = File.ReadAllBytes(FilePath);
            var uploadRequest = new UploadKycDocumentRequest
            {
                KycCheckId = KycCheckId,
                Type = "IDVSelfieImage",
                FileContent = fileBytes,
                FileName = Path.GetFileName(FilePath)
            };

            var content = CreateMultipartContent(uploadRequest);
            return ExecuteHttpRequest(content, UploadKycDocumentPath, signingCredentials);
        }

        private static HttpResponseMessage ExecutePingRequest(SigningCredentials signingCredentials)
        {
            var request = new PingRequest { Message = "ping" };
            var json = JsonConvert.SerializeObject(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            return ExecuteHttpRequest(content, PingPath, signingCredentials);
        }

        private static MultipartFormDataContent CreateMultipartContent(UploadKycDocumentRequest uploadRequest)
        {
            var fileContent = new ByteArrayContent(uploadRequest.FileContent);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

            var formDataContent = new MultipartFormDataContent();
            formDataContent.Add(new StringContent(uploadRequest.KycCheckId), "kyc_check_id");
            formDataContent.Add(new StringContent(uploadRequest.Type), "type");
            formDataContent.Add(fileContent, "file", uploadRequest.FileName);

            return formDataContent;
        }

        private static HttpResponseMessage ExecuteHttpRequest(HttpContent content, string path, SigningCredentials signingCredentials)
        {
            var requestBodyHash = CalculateRequestBodyHash(content.ReadAsByteArrayAsync().Result);
            var token = CreateToken(requestBodyHash, signingCredentials);
            Console.WriteLine("Request JWT token: " + token);

            using var client = new HttpClient();
            SetDefaultHeaders(client);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var apiPath = ApiUrl + path;
            var response = client.PostAsync(apiPath, content).Result;

            return response;
        }

        private static string CalculateRequestBodyHash(byte[] body)
        {
            using var sha256 = SHA256.Create();
            {
                var hash = SHA256.HashData(body);
                return Convert.ToBase64String(hash);
            }
        }

        private static string CreateToken(string requestBodyHash, SigningCredentials signingCredentials)
        {
            var claims = new[]
            {
                new Claim("sub", Subject),
                new Claim("rbh", requestBodyHash)
            };

            var notBefore = DateTime.UtcNow;
            var expires = DateTime.UtcNow.AddMinutes(1);
            var token = new JwtSecurityToken(Issuer, Audience, claims, notBefore, expires, signingCredentials);

            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(token);
        }

        private static void SetDefaultHeaders(HttpClient client)
        {
            client.DefaultRequestHeaders.Add("X-Audit-Source-Type", AuditSourceType);
            client.DefaultRequestHeaders.Add("X-Audit-User-Id", AuditUserId);
            client.DefaultRequestHeaders.Add("X-Product-Code", ProductCode);
        }

        private static void ValidateResponse(HttpResponseMessage response, SecurityKey wallesterPublicKey)
        {
            if (!response.Headers.TryGetValues("Authorization", out var bearerHeader))
            {
                Console.WriteLine("The response does not contain the Authorization header");
                return;
            }

            var responseToken = bearerHeader.FirstOrDefault()?.Replace("Bearer ", "");
            if (responseToken == null)
            {
                Console.WriteLine("The Authorization header is missing the Bearer token");
                return;
            }

            Console.WriteLine("Response JWT token: " + responseToken);
            var responseString = response.Content.ReadAsStringAsync().Result;
            var responseBodyHash = CalculateRequestBodyHash(Encoding.UTF8.GetBytes(responseString));

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

        private static void VerifyToken(string token, string responseBodyHash, SecurityKey wallesterPublicKey)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidAudience = Issuer,
                ValidateAudience = true,
                ValidIssuer = Audience,
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
            if (jwtToken.Subject != Subject)
            {
                throw new ApplicationException("invalid subject: " + jwtToken.Subject);
            }
        }
    }
}
