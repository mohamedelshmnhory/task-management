using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using System.Text.Json.Serialization;
using TodoApi;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;

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


// Serve static files from wwwroot and .well-known
app.UseStaticFiles(); // For wwwroot

// Serve .well-known directory
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(
        Path.Combine(Directory.GetCurrentDirectory(), ".well-known")),
    RequestPath = "/.well-known",
    ServeUnknownFileTypes = true // Needed for files without extensions
});

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

// Add static files middleware to serve uploaded files
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "uploads")),
    RequestPath = "/uploads"
});

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
        expires: DateTime.UtcNow.AddHours(jwtExpiryHours),
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
        .Select(u => new
        {
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
        .Include(p => p.Tasks)
        .Include(p => p.Members)
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
            tasksNumber = p.Tasks.Count(),
            completedTasksNumber = p.Tasks.Count(t => t.Status == TaskStatus.Done),
            membersNumber = p.Members.Count()
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
    await db.Tasks
        .Where(t => t.ProjectId == projectId)
        .Select(t => new
        {
            t.Id,
            t.Title,
            t.Description,
            t.ProjectId,
            t.AssignedUserId,
            t.Status,
            AssignedUserName = t.AssignedUser != null ? t.AssignedUser.UserName : null
        })
        .ToListAsync()
).RequireAuthorization();
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
    return Results.Ok(task);
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

    var members = project.Members.Select(u => new
    {
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

// --- Task Comments Endpoints ---
app.MapPost("/tasks/{id}/comments", async (int id, ClaimsPrincipal userPrincipal, TodoDb db, CommentInput input) =>
{
    var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (userId == null) return Results.Unauthorized();
    var task = await db.Tasks.FindAsync(id);
    if (task == null) return Results.NotFound(new ApiResponse(false, "Task not found"));
    var user = await db.Users.FindAsync(int.Parse(userId));
    if (user == null) return Results.Unauthorized();
    var comment = new Comment
    {
        Text = input.Text,
        TaskId = id,
        UserId = user.Id,
        CreatedAt = DateTime.UtcNow
    };
    db.Comments.Add(comment);
    await db.SaveChangesAsync();
    return Results.Created($"/tasks/{id}/comments/{comment.Id}", new
    {
        comment.Id,
        comment.Text,
        comment.CreatedAt,
        User = new
        {
            user.Id,
            user.UserName,
            user.Email,
            user.FullName
        }
    });
}).RequireAuthorization();

app.MapGet("/tasks/{id}/comments", async (int id, TodoDb db) =>
{
    var comments = await db.Comments
        .Where(c => c.TaskId == id)
        .OrderByDescending(c => c.CreatedAt)
        .Select(c => new
        {
            c.Id,
            c.Text,
            c.CreatedAt,
            User = new
            {
                c.User.Id,
                c.User.UserName,
                c.User.Email,
                c.User.FullName
            }
        })
        .ToListAsync();
    return Results.Ok(comments);
}).RequireAuthorization();

app.MapDelete("/tasks/{taskId}/comments/{commentId}", async (int taskId, int commentId, TodoDb db) =>
{
    var comment = await db.Comments.FindAsync(commentId);
    if (comment == null || comment.TaskId != taskId)
        return Results.NotFound(new ApiResponse(false, "Comment not found"));

    db.Comments.Remove(comment);
    await db.SaveChangesAsync();
    return Results.NoContent();
}).RequireAuthorization();

app.MapGet("/my-tasks", async (ClaimsPrincipal userPrincipal, TodoDb db) =>
{
    var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier) ?? userPrincipal.FindFirstValue(JwtRegisteredClaimNames.Sub);
    if (userId == null) return Results.Unauthorized();

    var tasks = await db.Tasks
        .Where(t => t.AssignedUserId == int.Parse(userId))
        .Select(t => new
        {
            t.Id,
            t.Title,
            t.Description,
            t.ProjectId,
            t.AssignedUserId,
            t.Status,
            AssignedUserName = t.AssignedUser != null ? t.AssignedUser.UserName : null
        })
        .ToListAsync();

    return Results.Ok(tasks);
}).RequireAuthorization();

// --- Task Attachments Endpoints ---
app.MapPost("/tasks/{id}/attachments", async (int id, HttpRequest request, TodoDb db) =>
{
    var task = await db.Tasks.FindAsync(id);
    if (task == null)
        return Results.NotFound(new ApiResponse(false, "Task not found"));

    if (!request.HasFormContentType)
        return Results.BadRequest(new ApiResponse(false, "No file uploaded"));

    var form = await request.ReadFormAsync();
    var file = form.Files.FirstOrDefault();
    if (file == null || file.Length == 0)
        return Results.BadRequest(new ApiResponse(false, "No file uploaded"));

    // Create uploads directory if it doesn't exist
    var uploadsDir = Path.Combine(Directory.GetCurrentDirectory(), "uploads", "tasks", id.ToString());
    Directory.CreateDirectory(uploadsDir);

    var fileName = $"{Guid.NewGuid()}_{Path.GetFileName(file.FileName)}";
    var filePath = Path.Combine(uploadsDir, fileName);

    using (var stream = new FileStream(filePath, FileMode.Create))
    {
        await file.CopyToAsync(stream);
    }

    var attachment = new Attachment
    {
        TaskId = id,
        FileName = file.FileName,
        FilePath = filePath,
        UploadedAt = DateTime.UtcNow
    };
    db.Attachments.Add(attachment);
    await db.SaveChangesAsync();

    // Generate proper URL for the attachment
    var baseUrl = $"{request.Scheme}://{request.Host}";
    var downloadUrl = $"{baseUrl}/files/{attachment.Id}";

    return Results.Created($"/tasks/{id}/attachments/{attachment.Id}", new
    {
        attachment.Id,
        attachment.FileName,
        attachment.UploadedAt,
        Url = downloadUrl
    });
}).RequireAuthorization();

app.MapGet("/tasks/{id}/attachments", async (HttpRequest request, int id, TodoDb db) =>
{
    var baseUrl = $"{request.Scheme}://{request.Host}";
    var attachments = await db.Attachments
        .Where(a => a.TaskId == id)
        .Select(a => new
        {
            a.Id,
            a.FileName,
            a.UploadedAt,
            Url = $"{baseUrl}/files/{a.Id}"
        })
        .ToListAsync();

    return Results.Ok(attachments);
}).RequireAuthorization();

// Dedicated file serving endpoint
app.MapGet("/api/attachments/{attachmentId}/download", async (int attachmentId, TodoDb db, ILogger<Program> logger) =>
{
    var attachment = await db.Attachments.FirstOrDefaultAsync(a => a.Id == attachmentId);
    if (attachment == null)
    {
        logger.LogWarning("Attachment not found: {AttachmentId}", attachmentId);
        return Results.NotFound(new ApiResponse(false, "Attachment not found"));
    }

    if (!File.Exists(attachment.FilePath))
    {
        logger.LogError("File not found on disk: {FilePath}", attachment.FilePath);
        return Results.NotFound(new ApiResponse(false, "File not found on disk"));
    }

    try
    {
        var fileBytes = await File.ReadAllBytesAsync(attachment.FilePath);
        logger.LogInformation("Serving file: {FileName}, Size: {Size} bytes", attachment.FileName, fileBytes.Length);

        // Determine content type based on file extension
        var ext = Path.GetExtension(attachment.FileName).ToLowerInvariant();
        var contentType = ext switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".bmp" => "image/bmp",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            ".pdf" => "application/pdf",
            ".txt" => "text/plain",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt" => "application/vnd.ms-powerpoint",
            ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".zip" => "application/zip",
            ".rar" => "application/x-rar-compressed",
            ".mp4" => "video/mp4",
            ".avi" => "video/x-msvideo",
            ".mov" => "video/quicktime",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            _ => "application/octet-stream"
        };

        logger.LogInformation("Content-Type: {ContentType} for file: {FileName}", contentType, attachment.FileName);

        return Results.File(fileBytes, contentType, attachment.FileName);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error serving file: {FileName}", attachment.FileName);
        return Results.StatusCode(500);
    }
}).RequireAuthorization();

// Public file serving endpoint (no authentication required for testing)
app.MapGet("/files/{attachmentId}", async (int attachmentId, TodoDb db, ILogger<Program> logger) =>
{
    var attachment = await db.Attachments.FirstOrDefaultAsync(a => a.Id == attachmentId);
    if (attachment == null)
    {
        logger.LogWarning("Attachment not found: {AttachmentId}", attachmentId);
        return Results.NotFound("File not found");
    }

    if (!File.Exists(attachment.FilePath))
    {
        logger.LogError("File not found on disk: {FilePath}", attachment.FilePath);
        return Results.NotFound("File not found on disk");
    }

    try
    {
        var fileBytes = await File.ReadAllBytesAsync(attachment.FilePath);
        logger.LogInformation("Serving file: {FileName}, Size: {Size} bytes", attachment.FileName, fileBytes.Length);

        // Determine content type based on file extension
        var ext = Path.GetExtension(attachment.FileName).ToLowerInvariant();
        var contentType = ext switch
        {
            ".jpg" or ".jpeg" => "image/jpeg",
            ".png" => "image/png",
            ".gif" => "image/gif",
            ".bmp" => "image/bmp",
            ".webp" => "image/webp",
            ".svg" => "image/svg+xml",
            ".pdf" => "application/pdf",
            ".txt" => "text/plain",
            ".doc" => "application/msword",
            ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls" => "application/vnd.ms-excel",
            ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt" => "application/vnd.ms-powerpoint",
            ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".zip" => "application/zip",
            ".rar" => "application/x-rar-compressed",
            ".mp4" => "video/mp4",
            ".avi" => "video/x-msvideo",
            ".mov" => "video/quicktime",
            ".mp3" => "audio/mpeg",
            ".wav" => "audio/wav",
            _ => "application/octet-stream"
        };

        logger.LogInformation("Content-Type: {ContentType} for file: {FileName}", contentType, attachment.FileName);

        return Results.File(fileBytes, contentType, attachment.FileName);
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error serving file: {FileName}", attachment.FileName);
        return Results.StatusCode(500);
    }
});

app.Run();