﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Text;
using GostCryptography.Pkcs;

namespace AspNet.Security.OAuth.Esia
{
    class EsiaClientSecret
    {
        public EsiaClientSecret(EsiaAuthenticationOptions options)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options));

            if (Options.ClientCertificate == null)
                throw new ArgumentException("Client certificate must be provided.");
        }

        public EsiaAuthenticationOptions Options { get; }

        public string State { get; private set; }
        public string Timestamp { get; private set; }
        public string Scope { get; private set; }
        public string Secret { get; private set; }

        public string GenerateClientSecret()
        {
            State = Options.State.ToString("D");
            Timestamp = DateTime.Now.ToString("yyyy.MM.dd HH:mm:ss zz00");
            Scope = FormatScope(Options.Scope);

            var signMessage = Scope + Timestamp + Options.ClientId + State;
            var encodedSignature = SignMessage(Encoding.UTF8.GetBytes(signMessage));
            Secret = EsiaHelpers.Base64UrlEncode(encodedSignature);

            return Secret;
        }

        private byte[] SignMessage(byte[] message)
        {
            var signedCms = new GostSignedCms(new ContentInfo(message), true);
            var cmsSigner = new CmsSigner(Options.ClientCertificate);
            signedCms.ComputeSignature(cmsSigner);
            return signedCms.Encode();
        }

        private static string FormatScope(IEnumerable<string> scopes) => String.Join(" ", scopes);
    }
}
