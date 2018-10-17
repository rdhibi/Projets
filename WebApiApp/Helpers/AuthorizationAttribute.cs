using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Http;

namespace WebApiApp.Helpers
{
    /// <summary>
    /// attribut d'autorisation
    /// </summary>
    public class AuthorizationAttribute : AuthorizeAttribute
    {

        public override void OnAuthorization(System.Web.Http.Controllers.HttpActionContext actionContext)
        {

            if (AuthorizeRequest(actionContext))
            {

                return;

            }

            HandleUnauthorizedRequest(actionContext);

        }

        protected override void HandleUnauthorizedRequest(System.Web.Http.Controllers.HttpActionContext actionContext)
        {

            actionContext.Response = new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Forbidden,
                Content = new StringContent("You are unauthorized to access this resource")
            };

        }

        private bool AuthorizeRequest(System.Web.Http.Controllers.HttpActionContext actionContext)
        {
            //signature user 1 mise sur coté client jquery pour le test
            //string sign1 = CreateHmac("user1@test.com");

            string Authorization = actionContext.Request.Headers.Authorization != null ? 
                actionContext.Request.Headers.Authorization.ToString().Replace("Basic ","") : "";

            string mail = "", signature = "";

            if (!Authorization.Contains(' ')) return false;

            mail = Authorization.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();

            signature = Authorization.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).LastOrDefault();

            if (string.IsNullOrEmpty(mail) || string.IsNullOrEmpty(signature)) return false;

            string signatureDB = CreateHmac(mail);

            return signatureDB == signature;
            

        }

        /// <summary>
        /// fonction qui doit être dans une classe de hashage(helper)
        /// </summary>
        /// <param name="toHash"></param>
        /// <returns></returns>
        private string CreateHmac( string toHash)
        {

            string hashPasswordHexa = "9ba1f63365a6caf66e46348f43cdef956015bea997adeb06e69007ee3ff517df10fc5eb860da3d43b82c2a040c931119d2dfc6d08e253742293a868cc2d82015"; 
            byte[] hashPassword = ConvertHexStringToByteArray(hashPasswordHexa);

            string hashString;

            using (var hmac = new HMACSHA512(hashPassword))
            {
                var hash = hmac.ComputeHash(Encoding.ASCII.GetBytes(toHash));
                hashString = BitConverter.ToString(hash).Replace("-", string.Empty).ToUpper();
            }
            return hashString;

        }

        private static byte[] ConvertHexStringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

    }
}