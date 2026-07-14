using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

var builder = WebApplication.CreateBuilder(args);

// 1. DATABASE CONFIGURATION & ENVIRONMENT PARSING
// Aiven outputs database URLs as 'mysql://user:pass@host:port/dbname'.
// This logic translates it into a format that Entity Framework understands.
string connectionString = "";
string? envString = Environment.GetEnvironmentVariable("CONNECTION_STRING");

if (!string.IsNullOrEmpty(envString))
{
    if (envString.StartsWith("mysql://"))
    {
        var uri = new Uri(envString);
        var userInfo = uri.UserInfo.Split(':');
        string user = userInfo[0];
        string password = userInfo.Length > 1 ? userInfo[1] : "";
        connectionString = $"Server={uri.Host};Port={uri.Port};Database={uri.AbsolutePath.TrimStart('/')};Uid={user};Pwd={password};SslMode=Required;";
    }
    else
    {
        connectionString = envString;
    }
}
else
{
    // Fallback default for local machine debugging if needed
    connectionString = "Server=localhost;Port=3306;Database=taskdb;Uid=root;Pwd=;";
}

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 30))));

// 2. CORS CONFIGURATION
// This allows your Vercel frontend to query this backend without security blocks.
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

var app = builder.Build();
app.UseCors("AllowAllOrigins");

// Ensure database and schema are safely initialized on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

// 3. REST API ENDPOINTS (MINIMAL API)

// GET: Fetch all tasks
app.MapGet("/api/tasks", async (AppDbContext db) =>
    await db.Tasks.OrderByDescending(t => t.CreatedAt).ToListAsync());

// POST: Add a new task
app.MapPost("/api/tasks", async (AppDbContext db, TaskItem task) =>
{
    task.CreatedAt = DateTime.UtcNow;
    db.Tasks.Add(task);
    await db.SaveChangesAsync();
    return Results.Created($"/api/tasks/{task.Id}", task);
});

// PUT: Modify or mark a task complete
app.MapPut("/api/tasks/{id}", async (AppDbContext db, int id, TaskItem updatedTask) =>
{
    var task = await db.Tasks.FindAsync(id);
    if (task is null) return Results.NotFound();

    task.Title = updatedTask.Title;
    task.Description = updatedTask.Description;
    task.IsCompleted = updatedTask.IsCompleted;
    task.Priority = updatedTask.Priority;
    task.DueDate = updatedTask.DueDate;
    task.Category = updatedTask.Category;

    await db.SaveChangesAsync();
    return Results.NoContent();
});

// DELETE: Remove a task
app.MapDelete("/api/tasks/{id}", async (AppDbContext db, int id) =>
{
    var task = await db.Tasks.FindAsync(id);
    if (task is null) return Results.NotFound();

    db.Tasks.Remove(task);
    await db.SaveChangesAsync();
    return Results.Ok(task);
});

app.Run();

// 4. DATA MODEL & CONTEXT DEFINITIONS
public class TaskItem
{
    public int Id { get; set; }
    [Required]
    public string Title { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsCompleted { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // New fields for enhanced task management
    public string Priority { get; set; } = "medium";   // low | medium | high | critical
    public DateTime? DueDate { get; set; }
    public string Category { get; set; } = "general";  // general | work | personal | shopping | health
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<TaskItem> Tasks => Set<TaskItem>();
}
