using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// ── DATABASE ──────────────────────────────────────────────────────────────────
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
    else { connectionString = envString; }
}
else
{
    connectionString = "Server=localhost;Port=3306;Database=taskdb;Uid=root;Pwd=;";
}

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseMySql(connectionString, new MySqlServerVersion(new Version(8, 0, 30))));

// ── CORS ──────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

var app = builder.Build();
app.UseCors("AllowAllOrigins");

// Global exception handler to prevent CORS errors on 500
app.Use(async (context, next) =>
{
    try
    {
        await next();
    }
    catch (Exception ex)
    {
        context.Response.StatusCode = 500;
        context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
        await context.Response.WriteAsJsonAsync(new { error = ex.Message, stack = ex.StackTrace });
    }
});

// ── STARTUP: SAFE SCHEMA INIT + DEFAULT ADMIN SEED ───────────────────────────
using (var scope = app.Services.CreateScope())
{
    try
    {
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.EnsureCreated(); // Safe — only creates tables that don't exist
        Console.WriteLine("✅ Database ready.");

        // Seed default admin if no users exist
        if (!db.Users.Any())
        {
            db.Users.Add(new AppUser
            {
                Name     = "Administrator",
                Username = "admin",
                Email    = "admin@company.com",
                PasswordHash = HashPassword("admin123"),
                Role     = "admin",
                CreatedAt = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
            Console.WriteLine("✅ Default admin seeded (admin / admin123).");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"⚠️ DB init failed: {ex.Message}");
    }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────
static string HashPassword(string password)
{
    var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(password));
    return Convert.ToHexString(bytes).ToLower();
}

static string GenerateToken() => Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");

static async Task<AppUser?> Authenticate(HttpContext ctx, AppDbContext db)
{
    if (!ctx.Request.Headers.TryGetValue("X-Session-Token", out var token)) return null;
    return await db.Users.FirstOrDefaultAsync(u => u.SessionToken == token.ToString());
}

// ══════════════════════════════════════════════════════════════════════════════
//  AUTH ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/login
app.MapPost("/api/auth/login", async (AppDbContext db, LoginRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Username and password required." });

    var hash = HashPassword(req.Password);
    var user = await db.Users.FirstOrDefaultAsync(u =>
        u.Username == req.Username.Trim().ToLower() && u.PasswordHash == hash);

    if (user is null) return Results.Unauthorized();

    // Generate fresh session token
    user.SessionToken = GenerateToken();
    await db.SaveChangesAsync();

    return Results.Ok(new
    {
        token    = user.SessionToken,
        role     = user.Role,
        name     = user.Name,
        userId   = user.Id,
        username = user.Username
    });
});

// POST /api/auth/signup
app.MapPost("/api/auth/signup", async (AppDbContext db, CreateUserRequest req) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Username and password are required." });

    var normalized = req.Username.Trim().ToLower();
    if (await db.Users.AnyAsync(u => u.Username == normalized))
        return Results.Conflict(new { error = "Username already exists." });

    var newUser = new AppUser
    {
        Name         = string.IsNullOrWhiteSpace(req.Name) ? req.Username : req.Name.Trim(),
        Username     = normalized,
        Email        = req.Email?.Trim() ?? "",
        EmployeeId   = req.EmployeeId?.Trim() ?? "",
        PasswordHash = HashPassword(req.Password),
        Role         = "user", // Hardcode to user, preventing privilege escalation
        SessionToken = GenerateToken(), // Log them in immediately
        CreatedAt    = DateTime.UtcNow
    };

    db.Users.Add(newUser);
    await db.SaveChangesAsync();

    return Results.Created($"/api/users/{newUser.Id}", new
    {
        token      = newUser.SessionToken,
        role       = newUser.Role,
        name       = newUser.Name,
        userId     = newUser.Id,
        username   = newUser.Username,
        employeeId = newUser.EmployeeId
    });
});

// POST /api/auth/logout
app.MapPost("/api/auth/logout", async (HttpContext ctx, AppDbContext db) =>
{
    var user = await Authenticate(ctx, db);
    if (user is not null) { user.SessionToken = null; await db.SaveChangesAsync(); }
    return Results.Ok();
});

// GET /api/auth/me
app.MapGet("/api/auth/me", async (HttpContext ctx, AppDbContext db) =>
{
    var user = await Authenticate(ctx, db);
    if (user is null) return Results.Unauthorized();
    return Results.Ok(new { userId = user.Id, name = user.Name, username = user.Username, role = user.Role, email = user.Email, employeeId = user.EmployeeId });
});

// GET /api/health
app.MapGet("/api/health", async (AppDbContext db) =>
{
    try {
        var canConnect = await db.Database.CanConnectAsync();
        var userCount = await db.Users.CountAsync(); // Will throw if table doesn't exist
        return Results.Ok(new { status = "OK", canConnect, userCount });
    } catch (Exception ex) {
        return Results.Ok(new { status = "ERROR", message = ex.Message, inner = ex.InnerException?.Message });
    }
});

// ══════════════════════════════════════════════════════════════════════════════
//  USER MANAGEMENT (admin only)
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/users
app.MapGet("/api/users", async (HttpContext ctx, AppDbContext db) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var users = await db.Users
        .OrderBy(u => u.Name)
        .Select(u => new { u.Id, u.Name, u.Username, u.Email, u.Role, u.EmployeeId, u.CreatedAt })
        .ToListAsync();

    return Results.Ok(users);
});

// POST /api/users
app.MapPost("/api/users", async (HttpContext ctx, AppDbContext db, CreateUserRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Username and password are required." });

    var normalized = req.Username.Trim().ToLower();
    if (await db.Users.AnyAsync(u => u.Username == normalized))
        return Results.Conflict(new { error = "Username already exists." });

    var newUser = new AppUser
    {
        Name         = req.Name?.Trim() ?? req.Username,
        Username     = normalized,
        Email        = req.Email?.Trim() ?? "",
        EmployeeId   = req.EmployeeId?.Trim() ?? "",
        PasswordHash = HashPassword(req.Password),
        Role         = req.Role == "admin" ? "admin" : "user",
        CreatedAt    = DateTime.UtcNow
    };

    db.Users.Add(newUser);
    await db.SaveChangesAsync();
    return Results.Created($"/api/users/{newUser.Id}", new { newUser.Id, newUser.Name, newUser.Username, newUser.Email, newUser.Role, newUser.EmployeeId });
});

// PUT /api/users/{id} — change password or role
app.MapPut("/api/users/{id}", async (HttpContext ctx, AppDbContext db, int id, UpdateUserRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();

    if (!string.IsNullOrWhiteSpace(req.Name))       user.Name       = req.Name.Trim();
    if (!string.IsNullOrWhiteSpace(req.Email))      user.Email      = req.Email.Trim();
    if (req.EmployeeId != null)                      user.EmployeeId = req.EmployeeId.Trim();
    if (!string.IsNullOrWhiteSpace(req.Password))   user.PasswordHash = HashPassword(req.Password);
    if (req.Role == "admin" || req.Role == "user")   user.Role       = req.Role;

    await db.SaveChangesAsync();
    return Results.Ok(new { user.Id, user.Name, user.Username, user.Email, user.Role, user.EmployeeId });
});

// DELETE /api/users/{id}
app.MapDelete("/api/users/{id}", async (HttpContext ctx, AppDbContext db, int id) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var user = await db.Users.FindAsync(id);
    if (user is null) return Results.NotFound();
    if (user.Id == caller.Id) return Results.BadRequest(new { error = "Cannot delete your own account." });

    // Unassign their tasks instead of deleting them
    var tasks = await db.Tasks.Where(t => t.AssignedToUserId == id).ToListAsync();
    foreach (var t in tasks) { t.AssignedToUserId = null; t.AssignedToName = "Unassigned"; }

    db.Users.Remove(user);
    await db.SaveChangesAsync();
    return Results.Ok();
});

// ══════════════════════════════════════════════════════════════════════════════
//  TASK ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/tasks — admin sees all, user sees only theirs
app.MapGet("/api/tasks", async (HttpContext ctx, AppDbContext db) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    IQueryable<TaskItem> query = db.Tasks.OrderByDescending(t => t.CreatedAt);
    if (caller.Role != "admin")
        query = query.Where(t => t.AssignedToUserId == caller.Id);

    return Results.Ok(await query.ToListAsync());
});

// POST /api/tasks — admin only
app.MapPost("/api/tasks", async (HttpContext ctx, AppDbContext db, TaskItem task) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    task.CreatedAt   = DateTime.UtcNow;
    task.CreatedByName = caller.Name;

    // Resolve assignee name
    if (task.AssignedToUserId.HasValue)
    {
        var assignee = await db.Users.FindAsync(task.AssignedToUserId.Value);
        task.AssignedToName = assignee?.Name ?? "Unknown";
    }

    db.Tasks.Add(task);
    await db.SaveChangesAsync();
    return Results.Created($"/api/tasks/{task.Id}", task);
});

// PUT /api/tasks/{id}
app.MapPut("/api/tasks/{id}", async (HttpContext ctx, AppDbContext db, int id, TaskItem updatedTask) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var task = await db.Tasks.FindAsync(id);
    if (task is null) return Results.NotFound();

    // Non-admin can only toggle completion on their own tasks
    if (caller.Role != "admin")
    {
        if (task.AssignedToUserId != caller.Id) return Results.Forbid();
        if (!task.IsCompleted && updatedTask.IsCompleted) task.CompletedAt = DateTime.UtcNow;
        if (task.IsCompleted && !updatedTask.IsCompleted) task.CompletedAt = null;
        task.IsCompleted = updatedTask.IsCompleted;
        await db.SaveChangesAsync();
        return Results.NoContent();
    }

    // Admin full edit
    task.Title       = updatedTask.Title;
    task.Description = updatedTask.Description;

    if (!task.IsCompleted && updatedTask.IsCompleted) task.CompletedAt = DateTime.UtcNow;
    else if (task.IsCompleted && !updatedTask.IsCompleted) task.CompletedAt = null;
    task.IsCompleted = updatedTask.IsCompleted;

    task.Priority = updatedTask.Priority;

    if (updatedTask.DueDate.HasValue && task.DueDate.HasValue && updatedTask.DueDate.Value > task.DueDate.Value)
        task.RescheduleCount += 1;
    task.DueDate = updatedTask.DueDate;

    task.Category      = updatedTask.Category;
    task.EnergyLevel   = updatedTask.EnergyLevel;
    task.RecurrenceRule = updatedTask.RecurrenceRule;

    // Re-assign
    if (updatedTask.AssignedToUserId.HasValue && updatedTask.AssignedToUserId != task.AssignedToUserId)
    {
        var assignee = await db.Users.FindAsync(updatedTask.AssignedToUserId.Value);
        task.AssignedToUserId = updatedTask.AssignedToUserId;
        task.AssignedToName   = assignee?.Name ?? "Unknown";
    }
    else if (!updatedTask.AssignedToUserId.HasValue)
    {
        task.AssignedToUserId = null;
        task.AssignedToName   = "Unassigned";
    }

    await db.SaveChangesAsync();
    return Results.NoContent();
});

// DELETE /api/tasks/{id} — admin only
app.MapDelete("/api/tasks/{id}", async (HttpContext ctx, AppDbContext db, int id) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var task = await db.Tasks.FindAsync(id);
    if (task is null) return Results.NotFound();

    db.Tasks.Remove(task);
    await db.SaveChangesAsync();
    return Results.Ok(task);
});

app.Run();

// ══════════════════════════════════════════════════════════════════════════════
//  DATA MODELS & CONTEXT
// ══════════════════════════════════════════════════════════════════════════════

public class AppUser
{
    public int      Id           { get; set; }
    [Required] public string Name { get; set; } = string.Empty;
    [Required] public string Username { get; set; } = string.Empty;
    public string   Email        { get; set; } = string.Empty;
    public string   EmployeeId   { get; set; } = string.Empty; // Optional employee identifier
    [Required] public string PasswordHash { get; set; } = string.Empty;
    public string   Role         { get; set; } = "user"; // admin | user
    public string?  SessionToken { get; set; }
    public DateTime CreatedAt    { get; set; } = DateTime.UtcNow;
    // NOTE: After deploying, run this on Aiven if EmployeeId column is missing:
    // ALTER TABLE Users ADD COLUMN EmployeeId VARCHAR(100) NOT NULL DEFAULT '';
}

public class TaskItem
{
    public int    Id          { get; set; }
    [Required] public string Title { get; set; } = string.Empty;
    public string? Description  { get; set; }
    public bool   IsCompleted   { get; set; } = false;
    public DateTime CreatedAt   { get; set; } = DateTime.UtcNow;
    public string Priority      { get; set; } = "medium";
    public DateTime? DueDate    { get; set; }
    public string Category      { get; set; } = "general";
    public string EnergyLevel   { get; set; } = "medium";
    public int    RescheduleCount { get; set; } = 0;
    public DateTime? CompletedAt  { get; set; }
    public string? RecurrenceRule { get; set; }

    // Assignment
    public int?   AssignedToUserId  { get; set; }
    public string AssignedToName    { get; set; } = "Unassigned";
    public string CreatedByName     { get; set; } = "Admin";
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<AppUser>  Users => Set<AppUser>();
    public DbSet<TaskItem> Tasks => Set<TaskItem>();
}

// ── REQUEST DTOs ──────────────────────────────────────────────────────────────
public record LoginRequest(string Username, string Password);
public record CreateUserRequest(string Username, string Password, string? Name, string? Email, string? Role, string? EmployeeId);
public record UpdateUserRequest(string? Name, string? Email, string? Password, string? Role, string? EmployeeId);