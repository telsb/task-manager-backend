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
        connectionString = $"Server={uri.Host};Port={uri.Port};Database={uri.AbsolutePath.TrimStart('/')};Uid={user};Pwd={password};SslMode=Required;AllowPublicKeyRetrieval=true;";
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
    try
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.EnsureDeleted(); // FORCE DROP AND RECREATE FOR NEW SCHEMA
        db.Database.EnsureCreated();
        Console.WriteLine("✅ Database connection successful.");
    }
    catch (Exception ex)
    {
        // Log but don't crash — the app can still serve requests
        Console.WriteLine($"⚠️ Database init failed: {ex.Message}");
    }
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
    
    // If transitioning to completed, set CompletedAt
    if (!task.IsCompleted && updatedTask.IsCompleted) {
        task.CompletedAt = DateTime.UtcNow;
    } else if (task.IsCompleted && !updatedTask.IsCompleted) {
        task.CompletedAt = null;
    }
    
    task.IsCompleted = updatedTask.IsCompleted;
    task.Priority = updatedTask.Priority;
    
    // Track rescheduling
    if (updatedTask.DueDate.HasValue && task.DueDate.HasValue && updatedTask.DueDate.Value > task.DueDate.Value) {
        task.RescheduleCount += 1;
    }
    task.DueDate = updatedTask.DueDate;
    
    task.Category = updatedTask.Category;
    task.EnergyLevel = updatedTask.EnergyLevel;
    task.RecurrenceRule = updatedTask.RecurrenceRule;
    
    // Allow resetting reschedule count from client
    if (updatedTask.RescheduleCount == 0) {
        task.RescheduleCount = 0;
    }

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
    
    // Additional fields for TaskFlow overhaul
    public string EnergyLevel { get; set; } = "medium"; // low | medium | high
    public int RescheduleCount { get; set; } = 0;
    public DateTime? CompletedAt { get; set; }
    public string? RecurrenceRule { get; set; }
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<TaskItem> Tasks => Set<TaskItem>();
}