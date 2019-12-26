using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Esia
{
    using System.Linq;
    using System.Text.Json;

    using Newtonsoft.Json.Linq;

    public class EsiaAuthenticationOptions : OAuthOptions
    {
        public EsiaAuthenticationOptions()
        {
            CallbackPath = new PathString("/signin-esia");
            AuthorizationEndpoint = EsiaAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = EsiaAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = EsiaAuthenticationDefaults.UserInformationEndpoint;

            Scope.Add(EsiaConstants.UserInformationScope);

            ClaimActions.MapJsonKey(ClaimTypes.DateOfBirth, "birthDate");
            ClaimActions.MapJsonKey(ClaimTypes.Gender, "gender");
            ClaimActions.MapJsonKey(ClaimTypes.GivenName, "firstName");
            ClaimActions.MapJsonKey(ClaimTypes.Surname, "lastName");
            ClaimActions.MapJsonKey(EsiaConstants.TrustedUrn, "trusted");
            ClaimActions.MapJsonKey(EsiaConstants.MiddleNameUrn, "middleName");
            ClaimActions.MapJsonKey(EsiaConstants.BirthPlaceUrn, "birthPlace");
            ClaimActions.MapJsonKey(EsiaConstants.CitizenshipUrn, "citizenship");
            ClaimActions.MapJsonKey(EsiaConstants.SnilsUrn, "snils");
            ClaimActions.MapJsonKey(EsiaConstants.InnUrn, "inn");
            ClaimActions.MapCustomJson(ClaimTypes.Name, ParseName);
            ClaimActions.MapCustomJson(ClaimTypes.Email, obj => ParseContactInfo(obj, "EML"));
            ClaimActions.MapCustomJson(ClaimTypes.MobilePhone, obj => ParseContactInfo(obj, "MBT"));
            ClaimActions.MapCustomJson(ClaimTypes.HomePhone, obj => ParseContactInfo(obj, "PHN"));
            ClaimActions.MapCustomJson(ClaimTypes.OtherPhone, obj => ParseContactInfo(obj, "CPH"));
        }

        public string AccessType { get; set; } = "online";

        public Guid State { get; } = Guid.NewGuid();

        public X509Certificate2 ClientCertificate { get; set; }

        public bool FetchContactInfo { get; set; } = false;

        public override void Validate()
        {
            try
            {
                base.Validate();
            }
            catch (ArgumentException e) when (e.ParamName == nameof(ClientSecret))
            {
                // Do nothing
            }
            catch (Exception)
            {
                throw;
            }
        }

        private static string ParseName(JsonElement obj)
        {
            var lastName = obj.GetString("lastName");
            var firstName = obj.GetString("firstName");
            var middleName = obj.GetString("middleName");
            return String.Join(" ", new[] { lastName, firstName, middleName }.Where(x => !String.IsNullOrEmpty(x)));
        }

        private static string ParseContactInfo(JsonElement obj, string key)
        {
            return string.Empty;
            //return obj.Value<JArray>("elements")?.FirstOrDefault(x => x["type"]?.ToString() == key)?["value"]?.ToString();
        }
    }
}
