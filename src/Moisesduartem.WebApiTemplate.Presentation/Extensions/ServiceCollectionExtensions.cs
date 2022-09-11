﻿using FluentValidation;
using FluentValidation.AspNetCore;
using MediatR;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Moisesduartem.WebApiTemplate.Application.V1.Options;
using Moisesduartem.WebApiTemplate.Application.V1.Services;
using Moisesduartem.WebApiTemplate.Application.V1.Users.Handlers;
using Moisesduartem.WebApiTemplate.Domain.V1.Users.Repositories;
using Moisesduartem.WebApiTemplate.Infra.Context;
using Moisesduartem.WebApiTemplate.Infra.Repositories;
using Moisesduartem.WebApiTemplate.Infra.Services;
using Serilog;
using System.Text;

namespace Moisesduartem.WebApiTemplate.Presentation.Extensions
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddDIConfiguration(this IServiceCollection services)
        {
            services.AddScoped<IUserRepository, UserRepository>();

            services.AddScoped<ITokenGenerationService, TokenGenerationService>();
            services.AddScoped<IAuthenticatedUserService, AuthenticatedUserService>();

            return services;
        }
        
        public static IServiceCollection AddEFCoreConfiguration(this IServiceCollection services, ConfigurationManager configuration)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

            return services;
        }

        public static IServiceCollection AddFluentValidationConfiguration(this IServiceCollection services)
        {
            services.AddValidatorsFromAssemblies(AppDomain.CurrentDomain.GetAssemblies());
            services.AddFluentValidationAutoValidation();

            return services;
        }

        public static IServiceCollection AddMediatorConfiguration(this IServiceCollection services)
        {
            services.AddMediatR(typeof(LoginQueryHandler).Assembly);
            
            return services;
        }
        
        public static IServiceCollection AddJwtConfiguration(this IServiceCollection services, ConfigurationManager configuration)
        {
            var authenticationSection = configuration.GetSection("Authentication");

            var secretKey = Encoding.ASCII.GetBytes(authenticationSection.GetValue<string>("Secret"));

            services.Configure<AuthenticationOptions>(authenticationSection);

            services
                .AddHttpContextAccessor()
                .AddAuthentication(x =>
                {
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(x =>
                {
                    x.RequireHttpsMetadata = false;
                    x.SaveToken = true;
                    x.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(secretKey),
                        ValidateIssuer = false,
                        ValidateAudience = false
                    };
                }); ;

            return services;
        }
    }
}