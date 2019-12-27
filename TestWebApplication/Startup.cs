using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Esia;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.EntityFrameworkCore;
using TestWebApplication.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TestWebApplication
{
    using System.Security.Cryptography.X509Certificates;

    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));
            services.AddDefaultIdentity<IdentityUser>(options => options.SignIn.RequireConfirmedAccount = true)
                .AddEntityFrameworkStores<ApplicationDbContext>();
            services.AddControllersWithViews();
            services.AddRazorPages();
            services.AddAuthentication().AddEsia(ConfigureEsia);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }

        private void ConfigureEsia(EsiaAuthenticationOptions options)
        {
            options.ClientId = "REGRDCPIR"; // идентификатор системы-клиента, обязателен
            options.ClientCertificate = FindClientSertificate(); // сертификат системы-клиента, обязателен

            // по умолчанию используются боевые адреса ЕСИА, можно поменять на тестовые:
            // options.AuthorizationEndpoint = EsiaConstants.TestAuthorizationUrl;
            // options.TokenEndpoint = EsiaConstants.TestAccessTokenUrl;
            // options.UserInformationEndpoint = EsiaConstants.TestUserInformationUrl;

            // получение контактных данных пользователя (почта, телефон), по умолчанию отключено
            // options.FetchContactInfo = true;
        }

        private X509Certificate2 FindClientSertificate()
        {
            // Будем искать сертификат в личном хранилище на локальной машине
            X509Store storeMy = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            storeMy.Open(OpenFlags.OpenExistingOnly);
            X509Certificate2Collection certColl = storeMy.Certificates.Find(X509FindType.FindBySerialNumber, "7cf9b04400010003f05d", false);

            storeMy.Close();

            return certColl.Count > 0 ? certColl[0] : new X509Certificate2();
        }
    }
}
