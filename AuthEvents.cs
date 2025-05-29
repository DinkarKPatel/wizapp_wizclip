using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System.Data;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net;
using System.Web;
using RestWizclipService.Models;

namespace RestWizclipService
{
    public class AuthEventsHandler : JwtBearerEvents
    {
        private const string BearerPrefix = "Bearer";

        private AuthEventsHandler() => OnMessageReceived = MessageReceivedHandler;

        /// <summary>
        /// Gets single available instance of <see cref="AuthEventsHandler"/>
        /// </summary>
        public static AuthEventsHandler Instance { get; } = new AuthEventsHandler();


        private Task MessageReceivedHandler(MessageReceivedContext context)
        {


            if (context.Request.Headers.TryGetValue("Authorization", out StringValues headerValue))
            {
                string token = headerValue;

                var bearerToken = context.Request.Headers[HeaderNames.Authorization].ToString().Replace("Bearer ", "");

                if (!string.IsNullOrEmpty(token))
                {

                    var handler = new JwtSecurityTokenHandler();
                    var jsonToken = handler.ReadToken(bearerToken);
                    var jwtSecurityToken = jsonToken as JwtSecurityToken;


                    var claims = jwtSecurityToken.Claims.ToList();

                    int nClaims = claims.Count();

                    string[,] TokenInfo = new string[nClaims, 2];
                    int n = 0;
                    foreach (var claim in claims)
                    {
                        if (claim.Type.ToUpper() == "ROLECODE")
                            context.Request.HttpContext.Session.SetString("roleCode", claim.Value);
                        else
                        if (claim.Type.ToUpper() == "USERID")
                            context.Request.HttpContext.Session.SetString("userId", claim.Value);
                        else
                        if (claim.Type.ToUpper() == "TOKENTYPE")
                            context.Request.HttpContext.Session.SetString("tokenType", claim.Value);
                        else
                        if (claim.Type.ToUpper() == "APIACCESS")
                            context.Request.HttpContext.Session.SetString("apiAccess", claim.Value);
                        else
                        if (claim.Type.ToUpper() == "APIGROUPCODE")
                            context.Request.HttpContext.Session.SetString("apiGroupCode", claim.Value);
                        else
                        if (claim.Type.ToUpper() == "WIZCLIPGROUPCODE")
                            context.Request.HttpContext.Session.SetString("wizclipGroupCode", claim.Value);

                    }
                }


                context.Token = bearerToken;
            }

            return Task.CompletedTask;
        }
    }
}
