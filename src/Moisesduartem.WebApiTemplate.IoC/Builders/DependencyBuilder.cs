﻿using FluentValidation;
using FluentValidation.AspNetCore;
using MediatR;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moisesduartem.WebApiTemplate.Application.V1.Services;
using Moisesduartem.WebApiTemplate.Application.V1.Users.Handlers;
using Moisesduartem.WebApiTemplate.Domain.V1.Users.Repositories;
using Moisesduartem.WebApiTemplate.Infra.MappingProfiles;
using Moisesduartem.WebApiTemplate.Infra.Repositories;
using Moisesduartem.WebApiTemplate.Infra.Services;
using System.Text;

namespace Moisesduartem.WebApiTemplate.IoC.Builders
{
    public class DependencyBuilder
    {
        private readonly IConfiguration _configuration;
        private readonly IServiceCollection _services;

        public DependencyBuilder(IConfiguration configuration, IServiceCollection services)
        {
            _configuration = configuration;
            _services = services;
        }

        public DependencyBuilder AddApiVersioning()
        {
            _services.AddApiVersioning(options =>
            {
                options.DefaultApiVersion = new ApiVersion(1, 0);
                options.ReportApiVersions = true;
                options.AssumeDefaultVersionWhenUnspecified = true;
                options.ApiVersionReader = ApiVersionReader.Combine(
                    new HeaderApiVersionReader("api-version"),
                    new UrlSegmentApiVersionReader()
                );
            });

            return this;
        }

        public DependencyBuilder AddAutoMapper()
        {
            _services.AddAutoMapper(cfg =>
            {
                cfg.AddProfile<UserProfile>();
            });
            return this;
        }

        public DependencyBuilder AddInjectedDependencies()
        {
            _services.AddScoped<IUserRepository, UserRepository>();
            _services.AddScoped<ITokenGenerationService, TokenGenerationService>();
            return this;
        }

        public DependencyBuilder AddFluentValidation()
        {
            _services.AddValidatorsFromAssemblies(AppDomain.CurrentDomain.GetAssemblies());
            _services.AddFluentValidationAutoValidation();
            return this;
        }

        public DependencyBuilder AddMediatR()
        {
            _services.AddMediatR(typeof(LoginQueryHandler).Assembly);
            return this;
        }
        
        public DependencyBuilder AddJwtAuthentication()
        {
            var secretKey = Encoding.ASCII.GetBytes("fedaf7d8863b48e197b9287d492b708e");

            _services
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

            return this;
        }
    }
}
