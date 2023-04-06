using AuthBackendExample.Models;
using AuthBackendExample.Data;
using AuthBackendExample.Services.AuthServices;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDbContext<AuthContext>(_ => _.UseSqlite(builder.Configuration.GetConnectionString("DbConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthContext>()
    .AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(_ =>
{
    _.Password.RequireNonAlphanumeric = false;
    _.Password.RequireUppercase = false;
    _.Password.RequireDigit = false;
    _.Password.RequiredLength = 3;
});

builder.Services.AddScoped<iAuthServices, AuthServices>();

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(_ =>
{
    _.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
    {
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http
    });

    _.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = JwtBearerDefaults.AuthenticationScheme,
                    Type = ReferenceType.SecurityScheme
                }
            },
            Array.Empty<string>()
        }
    });
});

builder.Services.AddAuthentication(_ =>
{
    _.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    _.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    _.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ =>
{
    _.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidIssuer = builder.Configuration.GetSection("JWT").GetValue<string>("issuer"),
        ValidAudience = builder.Configuration.GetSection("JWT").GetValue<string>("audience"),
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetSection("JWT").GetValue<string>("secret")))
    };
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors(_ =>
{
    _.AllowAnyOrigin().AllowCredentials().AllowAnyHeader().AllowAnyMethod();
});

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
