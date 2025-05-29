using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using System.Threading.Tasks;
using RestWizclipService.Models;


namespace RestWizclipService.Middlewares
{
    // You may need to install the Microsoft.AspNetCore.Http.Abstractions package into your project
    public class myCustomMiddleware
    {
        private readonly RequestDelegate _next;
        public IServiceProvider _serviceProvider;
        public myCustomMiddleware(RequestDelegate next, IConfiguration _config)
        {
            _next = next;
            AppConfigModel.globalConnConfig = _config;
        }

        public async Task Invoke(HttpContext httpContext, IServiceProvider serviceProvider)
        {

            string apiFullName = "";
            var controllerName = httpContext.GetRouteData().Values["controller"];
            var actionName = httpContext.GetRouteData().Values["action"];

            if (controllerName is object && actionName is object)
                apiFullName = controllerName.ToString().ToUpper() + "." + actionName.ToString().ToUpper();


            httpContext.Session.SetString("apiFullName", apiFullName);

            var GroupCode = httpContext.Request.Query.FirstOrDefault(q => string.Equals(q.Key, "Groupcode", StringComparison.OrdinalIgnoreCase)).Value;

            if (!string.IsNullOrEmpty(GroupCode) && (apiFullName == "AUTH.AUTHENTICATEUSER" || controllerName.ToString().ToUpper() == "WEBSOCKET"))
            {
                httpContext.Session.SetString("apiGroupCode", GroupCode.ToString());
                //sessionVariableService.apiGroupCode = GroupCode.ToString();
            }

            string tokenType = httpContext.Session.GetString("tokenType");

            if (tokenType == "2" && apiFullName != "TOKEN.REISSUEACCESSTOKEN"
                && apiFullName != "AUTH.GETUSERS" && apiFullName != "AUTH.AUTHENTICATEUSER")
            {

                HttpResponseMessage response = new HttpResponseMessage();

                httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
                await httpContext.Response.WriteAsync("API call with Refresh token is not allowed...");

                return;
            }

            if (tokenType == "1" && apiFullName == "TOKEN.REISSUEACCESSTOKEN")
            {

                HttpResponseMessage response = new HttpResponseMessage();

                httpContext.Response.StatusCode = StatusCodes.Status403Forbidden;
                await httpContext.Response.WriteAsync("New Access token cannot be issued with Bearer access token...");

                return;
            }

            _serviceProvider = serviceProvider;
            await _next(httpContext);
        }
    }

    // Extension method used to add the middleware to the HTTP request pipeline.
    public static class CustomMiddlewareExtensions
    {
        public static IApplicationBuilder UseCustomMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<myCustomMiddleware>();
        }
    }
}
