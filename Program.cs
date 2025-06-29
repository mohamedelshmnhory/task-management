using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Configure JSON serialization to handle circular references
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.WriteIndented = true;
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.CamelCase));
});

// Get settings from configuration
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var jwtKey = jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key not found in configuration");
var jwtIssuer = jwtSettings["Issuer"] ?? "TodoApi";
var jwtExpiryHours = int.Parse(jwtSettings["ExpiryInHours"] ?? "2");

// Get connection string from configuration
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

builder.Services.AddDbContext<TodoDb>(opt => 
    opt.UseSqlServer(connectionString));

builder.Services.AddDatabaseDeveloperPageExceptionFilter();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApiDocument(config =>
{
    config.DocumentName = "TodoAPI";
    config.Title = "TodoAPI v1";
    config.Version = "v1";
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseOpenApi();
    app.UseSwaggerUi(config =>
    {
        config.DocumentTitle = "TodoAPI";
        config.Path = "/swagger";
        config.DocumentPath = "/swagger/{documentName}/swagger.json";
        config.DocExpansion = "list";
    });
}

app.UseAuthentication();
app.UseAuthorization();

// Helper function for hashing passwords
string HashPassword(string password)
{
    using var sha = SHA256.Create();
    var bytes = Encoding.UTF8.GetBytes(password);
    var hash = sha.ComputeHash(bytes);
    return Convert.ToBase64String(hash);
}

// --- User Endpoints ---
app.MapPost("/register", async (User user, TodoDb db) =>
{
    if (string.IsNullOrWhiteSpace(user.UserName) || string.IsNullOrWhiteSpace(user.Email) || string.IsNullOrWhiteSpace(user.PasswordHash))
        return Results.BadRequest(new ApiResponse(false, "Username, Email, and Password are required."));
    if (await db.Users.AnyAsync(u => u.UserName == user.UserName || u.Email == user.Email))
        return Results.BadRequest(new ApiResponse(false, "Username or Email already exists."));
    user.PasswordHash = HashPassword(user.PasswordHash);
    db.Users.Add(user);
    await db.SaveChangesAsync();

    // Generate JWT token for the new user
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
        new Claim(JwtRegisteredClaimNames.Email, user.Email)
    };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: null,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(jwtExpiryHours),
        signingCredentials: creds
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { token = tokenString, user });
});

app.MapPost("/login", async (User login, TodoDb db) =>
{
    var hashed = HashPassword(login.PasswordHash);
    var user = await db.Users.FirstOrDefaultAsync(u => u.UserName == login.UserName && u.PasswordHash == hashed);
    if (user == null) 
        return Results.Json(new ApiResponse(false, "Invalid username or password."), statusCode: 400);
    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
        new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
        new Claim(JwtRegisteredClaimNames.Email, user.Email)
    };
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: null,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(2),
        signingCredentials: creds
    );
    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { token = tokenString, user });
});

app.MapGet("/profile", async (ClaimsPrincipal userPrincipal, TodoDb db) =>
{
    var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (userId == null) return Results.Unauthorized();
    var user = await db.Users.FindAsync(int.Parse(userId));
    if (user == null) return Results.NotFound();
    return Results.Ok(user);
}).RequireAuthorization();

app.MapPut("/profile", async (ClaimsPrincipal userPrincipal, User input, TodoDb db) =>
{
    var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (userId == null) return Results.Unauthorized();
    var user = await db.Users.FindAsync(int.Parse(userId));
    if (user == null) return Results.NotFound();
    user.FullName = input.FullName;
    user.Email = input.Email;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

app.MapGet("/users", async (TodoDb db) =>
    await db.Users
        .Select(u => new {
            u.Id,
            u.UserName,
            u.Email,
            u.FullName
        })
        .ToListAsync()
).RequireAuthorization();

// --- Project Endpoints ---
app.MapGet("/projects", async (TodoDb db) => 
    await db.Projects
        .Include(p => p.Owner)
        .Select(p => new 
        {
            p.Id,
            p.Name,
            p.Description,
            p.OwnerId,
            Owner = new 
            {
                p.Owner.Id,
                p.Owner.UserName,
                p.Owner.Email,
                p.Owner.FullName
            }
        })
        .ToListAsync()).RequireAuthorization();
app.MapGet("/projects/{id}", async (int id, TodoDb db) =>
{
    var project = await db.Projects
        .Include(p => p.Owner)
        .Include(p => p.Tasks)
        .Where(p => p.Id == id)
        .Select(p => new
        {
            p.Id,
            p.Name,
            p.Description,
            p.OwnerId,
            Owner = new
            {
                p.Owner.Id,
                p.Owner.UserName,
                p.Owner.Email,
                p.Owner.FullName
            },
            Tasks = p.Tasks.Select(t => new
            {
                t.Id,
                t.Title,
                t.Description,
                t.ProjectId,
                t.AssignedUserId,
                t.Status
            }),
            Members = p.Members.Select(u => new 
            {
                u.Id,
                u.UserName,
                u.Email,
                u.FullName
            })
        })
        .FirstOrDefaultAsync();
    
    return project != null ? Results.Ok(project) : Results.NotFound();
}).RequireAuthorization();
app.MapPost("/projects", async (ClaimsPrincipal userPrincipal, Project project, TodoDb db) =>
{
    var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (userId == null) return Results.Unauthorized();
    project.OwnerId = int.Parse(userId);
    db.Projects.Add(project);
    await db.SaveChangesAsync();
    return Results.Created($"/projects/{project.Id}", project);
}).RequireAuthorization();
app.MapPut("/projects/{id}", async (int id, Project input, TodoDb db) =>
{
    var project = await db.Projects.FindAsync(id);
    if (project == null) return Results.NotFound();
    project.Name = input.Name;
    project.Description = input.Description;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();
app.MapDelete("/projects/{id}", async (int id, TodoDb db) =>
{
    var project = await db.Projects.FindAsync(id);
    if (project == null) return Results.NotFound();
    db.Projects.Remove(project);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// --- Task Endpoints ---
app.MapGet("/projects/{projectId}/tasks", async (int projectId, TodoDb db) =>
    await db.Tasks.Where(t => t.ProjectId == projectId).ToListAsync()).RequireAuthorization();
app.MapGet("/tasks/{id}", async (int id, TodoDb db) =>
{
    var task = await db.Tasks
        .Include(t => t.AssignedUser)
        .Where(t => t.Id == id)
        .Select(t => new 
        {
            t.Id,
            t.Title,
            t.Description,
            t.ProjectId,
            t.AssignedUserId,
            t.Status,
            AssignedUser = t.AssignedUser != null ? new 
            {
                t.AssignedUser.Id,
                t.AssignedUser.UserName,
                t.AssignedUser.Email,
                t.AssignedUser.FullName
            } : null
        })
        .FirstOrDefaultAsync();
    
    return task != null ? Results.Ok(task) : Results.NotFound();
}).RequireAuthorization();
app.MapPost("/projects/{projectId}/tasks", async (int projectId, Task task, TodoDb db) =>
{
    task.ProjectId = projectId;
    db.Tasks.Add(task);
    await db.SaveChangesAsync();
    return Results.Created($"/tasks/{task.Id}", task);
}).RequireAuthorization();
app.MapPut("/tasks/{id}", async (int id, Task input, TodoDb db) =>
{
    var task = await db.Tasks.FindAsync(id);
    if (task == null) return Results.NotFound();
    task.Title = input.Title;
    task.Description = input.Description;
    task.Status = input.Status;
    task.AssignedUserId = input.AssignedUserId;
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();
app.MapDelete("/tasks/{id}", async (int id, TodoDb db) =>
{
    var task = await db.Tasks.FindAsync(id);
    if (task == null) return Results.NotFound();
    db.Tasks.Remove(task);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

// --- Project Members Endpoints ---
app.MapGet("/projects/{id}/members", async (int id, TodoDb db) =>
{
    var project = await db.Projects
        .Include(p => p.Members)
        .FirstOrDefaultAsync(p => p.Id == id);

    if (project == null)
        return Results.NotFound(new ApiResponse(false, "Project not found"));

    var members = project.Members.Select(u => new {
        u.Id,
        u.UserName,
        u.Email,
        u.FullName
    });

    return Results.Ok(members);
}).RequireAuthorization();

app.MapPost("/projects/{id}/members", async (int id, int userId, TodoDb db) =>
{
    var project = await db.Projects.Include(p => p.Members).FirstOrDefaultAsync(p => p.Id == id);
    var user = await db.Users.FindAsync(userId);

    if (project == null || user == null)
        return Results.BadRequest(new ApiResponse(false, "Project or user not found"));

    if (project.Members.Any(u => u.Id == userId))
        return Results.BadRequest(new ApiResponse(false, "User already a member"));

    project.Members.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok(new ApiResponse(true, "User added to project"));
}).RequireAuthorization();

app.MapDelete("/projects/{id}/members/{userId}", async (int id, int userId, TodoDb db) =>
{
    var project = await db.Projects.Include(p => p.Members).FirstOrDefaultAsync(p => p.Id == id);
    var user = await db.Users.FindAsync(userId);

    if (project == null || user == null)
        return Results.BadRequest(new ApiResponse(false, "Project or user not found"));

    if (!project.Members.Any(u => u.Id == userId))
        return Results.BadRequest(new ApiResponse(false, "User is not a member"));

    project.Members.Remove(user);
    await db.SaveChangesAsync();
    return Results.Ok(new ApiResponse(true, "User removed from project"));
}).RequireAuthorization();

app.Run();