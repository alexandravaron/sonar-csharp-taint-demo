using SonarCSharpDemo.Services;
using SonarCSharpDemo.Data;
using SonarCSharpDemo.Utils;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Register our vulnerable services for demonstration
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IDataRepository, DataRepository>();
builder.Services.AddScoped<FileManager>();
builder.Services.AddScoped<ReportGenerator>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
