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

// Automatically create tables if they don't exist
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    try
    {
        string initSql = @"
CREATE TABLE IF NOT EXISTS `Groups` (
    `Id` int NOT NULL AUTO_INCREMENT,
    `Name` varchar(200) NOT NULL,
    `Description` varchar(500) NULL,
    `CreatedByUserId` int NOT NULL,
    `CreatedAt` datetime(6) NOT NULL,
    CONSTRAINT `PK_Groups` PRIMARY KEY (`Id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS `GroupMembers` (
    `Id` int NOT NULL AUTO_INCREMENT,
    `GroupId` int NOT NULL,
    `UserId` int NOT NULL,
    `Status` varchar(20) NOT NULL DEFAULT 'pending',
    `JoinedAt` datetime(6) NULL,
    CONSTRAINT `PK_GroupMembers` PRIMARY KEY (`Id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS `Notifications` (
    `Id` int NOT NULL AUTO_INCREMENT,
    `UserId` int NOT NULL,
    `Type` varchar(50) NOT NULL,
    `Title` varchar(200) NOT NULL,
    `Body` varchar(500) NOT NULL,
    `Payload` longtext NULL,
    `IsRead` tinyint(1) NOT NULL DEFAULT 0,
    `CreatedAt` datetime(6) NOT NULL,
    CONSTRAINT `PK_Notifications` PRIMARY KEY (`Id`)
) CHARACTER SET=utf8mb4;

CREATE TABLE IF NOT EXISTS `ChatMessages` (
    `Id` int NOT NULL AUTO_INCREMENT,
    `GroupId` int NOT NULL,
    `SenderUserId` int NOT NULL,
    `SenderName` varchar(200) NOT NULL,
    `Body` longtext NOT NULL,
    `CreatedAt` datetime(6) NOT NULL,
    CONSTRAINT `PK_ChatMessages` PRIMARY KEY (`Id`)
) CHARACTER SET=utf8mb4;
";
        db.Database.ExecuteSqlRaw(initSql);
        Console.WriteLine("Database schema verified/created successfully.");
    }
    catch (Exception ex)
    {
        Console.WriteLine("Error verifying database schema: " + ex.Message);
    }
}

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
        var userCount = await db.Users.CountAsync();
        var taskCount = await db.Tasks.CountAsync();
        return Results.Ok(new { status = "OK", canConnect, userCount, taskCount });
    } catch (Exception ex) {
        return Results.Ok(new { status = "ERROR", message = ex.Message, inner = ex.InnerException?.Message });
    }
});

// GET /api/script
app.MapGet("/api/script", (AppDbContext db) => 
{
    return Results.Text(db.Database.GenerateCreateScript(), "text/plain");
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

// ══════════════════════════════════════════════════════════════════════════════
//  GROUP ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/groups — get groups you are a member of (or all if admin)
app.MapGet("/api/groups", async (HttpContext ctx, AppDbContext db) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var memberGroupIds = await db.GroupMembers
        .Where(m => m.UserId == caller.Id && m.Status == "accepted")
        .Select(m => m.GroupId)
        .ToListAsync();

    IQueryable<Group> query = db.Groups.OrderByDescending(g => g.CreatedAt);
    if (caller.Role != "admin")
        query = query.Where(g => memberGroupIds.Contains(g.Id));

    var groups = await query.ToListAsync();
    var result = new List<object>();
    foreach (var g in groups)
    {
        var memberCount = await db.GroupMembers.CountAsync(m => m.GroupId == g.Id && m.Status == "accepted");
        result.Add(new { g.Id, g.Name, g.Description, g.CreatedByUserId, g.CreatedAt, memberCount });
    }
    return Results.Ok(result);
});

// POST /api/groups — admin creates a group
app.MapPost("/api/groups", async (HttpContext ctx, AppDbContext db, CreateGroupRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var group = new Group
    {
        Name = req.Name.Trim(),
        Description = req.Description?.Trim() ?? "",
        CreatedByUserId = caller.Id,
        CreatedAt = DateTime.UtcNow
    };
    db.Groups.Add(group);
    await db.SaveChangesAsync();

    // Auto-add creator as accepted member
    db.GroupMembers.Add(new GroupMember { GroupId = group.Id, UserId = caller.Id, Status = "accepted", JoinedAt = DateTime.UtcNow });
    await db.SaveChangesAsync();

    return Results.Created($"/api/groups/{group.Id}", new { group.Id, group.Name, group.Description });
});

// DELETE /api/groups/{id} — admin deletes a group
app.MapDelete("/api/groups/{id}", async (HttpContext ctx, AppDbContext db, int id) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var group = await db.Groups.FindAsync(id);
    if (group is null) return Results.NotFound();

    var members = db.GroupMembers.Where(m => m.GroupId == id);
    db.GroupMembers.RemoveRange(members);
    var messages = db.ChatMessages.Where(m => m.GroupId == id);
    db.ChatMessages.RemoveRange(messages);
    db.Groups.Remove(group);
    await db.SaveChangesAsync();
    return Results.Ok();
});

// POST /api/groups/{id}/invite — admin invites users to a group
app.MapPost("/api/groups/{id}/invite", async (HttpContext ctx, AppDbContext db, int id, InviteRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var group = await db.Groups.FindAsync(id);
    if (group is null) return Results.NotFound();

    foreach (var userId in req.UserIds)
    {
        var user = await db.Users.FindAsync(userId);
        if (user is null) continue;

        var existing = await db.GroupMembers.FirstOrDefaultAsync(m => m.GroupId == id && m.UserId == userId);
        if (existing is not null) continue; // Already a member or pending

        db.GroupMembers.Add(new GroupMember { GroupId = id, UserId = userId, Status = "pending" });

        // Create notification
        db.Notifications.Add(new Notification
        {
            UserId = userId,
            Type = "group_invite",
            Title = $"Group Invitation: {group.Name}",
            Body = $"{caller.Name} invited you to join the group '{group.Name}'.",
            Payload = $"{{\"groupId\":{id},\"groupName\":\"{group.Name}\"}}",
            IsRead = false,
            CreatedAt = DateTime.UtcNow
        });
    }
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Invitations sent." });
});

// POST /api/groups/{id}/respond — user accepts or declines invitation
app.MapPost("/api/groups/{id}/respond", async (HttpContext ctx, AppDbContext db, int id, RespondRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var membership = await db.GroupMembers.FirstOrDefaultAsync(m => m.GroupId == id && m.UserId == caller.Id);
    if (membership is null) return Results.NotFound();

    membership.Status = req.Action == "accept" ? "accepted" : "declined";
    if (req.Action == "accept") membership.JoinedAt = DateTime.UtcNow;

    // Mark related notification as read
    if (req.NotificationId.HasValue)
    {
        var notif = await db.Notifications.FindAsync(req.NotificationId.Value);
        if (notif is not null) notif.IsRead = true;
    }

    await db.SaveChangesAsync();
    return Results.Ok(new { status = membership.Status });
});

// GET /api/groups/{groupId}/members — get accepted members of a group
app.MapGet("/api/groups/{groupId}/members", async (HttpContext ctx, AppDbContext db, int groupId) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var members = await db.GroupMembers
        .Where(m => m.GroupId == groupId && m.Status == "accepted")
        .ToListAsync();

    var result = new List<object>();
    foreach (var m in members)
    {
        var user = await db.Users.FindAsync(m.UserId);
        if (user is not null)
            result.Add(new { user.Id, user.Name, user.Username, user.Role, m.Status, m.JoinedAt });
    }
    return Results.Ok(result);
});

// DELETE /api/groups/{groupId}/members/{userId} — admin removes a member
app.MapDelete("/api/groups/{groupId}/members/{userId}", async (HttpContext ctx, AppDbContext db, int groupId, int userId) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var membership = await db.GroupMembers.FirstOrDefaultAsync(m => m.GroupId == groupId && m.UserId == userId);
    if (membership is null) return Results.NotFound();

    db.GroupMembers.Remove(membership);
    await db.SaveChangesAsync();
    return Results.Ok(new { message = "Member removed." });
});

// ══════════════════════════════════════════════════════════════════════════════
//  NOTIFICATION ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/notifications
app.MapGet("/api/notifications", async (HttpContext ctx, AppDbContext db) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var notifs = await db.Notifications
        .Where(n => n.UserId == caller.Id)
        .OrderByDescending(n => n.CreatedAt)
        .Take(50)
        .ToListAsync();

    return Results.Ok(notifs);
});

// POST /api/notifications/{id}/read
app.MapPost("/api/notifications/{id}/read", async (HttpContext ctx, AppDbContext db, int id) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var notif = await db.Notifications.FindAsync(id);
    if (notif is null || notif.UserId != caller.Id) return Results.NotFound();
    notif.IsRead = true;
    await db.SaveChangesAsync();
    return Results.Ok();
});

// POST /api/notifications/read-all
app.MapPost("/api/notifications/read-all", async (HttpContext ctx, AppDbContext db) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var unread = await db.Notifications.Where(n => n.UserId == caller.Id && !n.IsRead).ToListAsync();
    foreach (var n in unread) n.IsRead = true;
    await db.SaveChangesAsync();
    return Results.Ok();
});

// ══════════════════════════════════════════════════════════════════════════════
//  BULK TASK ENDPOINT
// ══════════════════════════════════════════════════════════════════════════════

// POST /api/tasks/bulk — admin sends one task to multiple users
app.MapPost("/api/tasks/bulk", async (HttpContext ctx, AppDbContext db, BulkTaskRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();
    if (caller.Role != "admin") return Results.Forbid();

    var created = new List<TaskItem>();
    foreach (var userId in req.UserIds)
    {
        var user = await db.Users.FindAsync(userId);
        if (user is null) continue;

        var task = new TaskItem
        {
            Title          = req.Title,
            Description    = req.Description,
            Priority       = req.Priority ?? "medium",
            Category       = req.Category ?? "general",
            DueDate        = req.DueDate,
            EnergyLevel    = "medium",
            AssignedToUserId = userId,
            AssignedToName = user.Name,
            CreatedByName  = caller.Name,
            CreatedAt      = DateTime.UtcNow
        };
        db.Tasks.Add(task);
        created.Add(task);
    }
    await db.SaveChangesAsync();
    return Results.Ok(new { count = created.Count, message = $"{created.Count} task(s) created." });
});

// ══════════════════════════════════════════════════════════════════════════════
//  CHAT ENDPOINTS
// ══════════════════════════════════════════════════════════════════════════════

// GET /api/chat/{groupId} — get last 100 messages
app.MapGet("/api/chat/{groupId}", async (HttpContext ctx, AppDbContext db, int groupId) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    // Must be an accepted member
    var isMember = await db.GroupMembers.AnyAsync(m => m.GroupId == groupId && m.UserId == caller.Id && m.Status == "accepted");
    if (!isMember && caller.Role != "admin") return Results.Forbid();

    var messages = await db.ChatMessages
        .Where(m => m.GroupId == groupId)
        .OrderBy(m => m.CreatedAt)
        .Take(100)
        .ToListAsync();

    return Results.Ok(messages);
});

// POST /api/chat/{groupId} — send a message
app.MapPost("/api/chat/{groupId}", async (HttpContext ctx, AppDbContext db, int groupId, SendMessageRequest req) =>
{
    var caller = await Authenticate(ctx, db);
    if (caller is null) return Results.Unauthorized();

    var isMember = await db.GroupMembers.AnyAsync(m => m.GroupId == groupId && m.UserId == caller.Id && m.Status == "accepted");
    if (!isMember && caller.Role != "admin") return Results.Forbid();

    if (string.IsNullOrWhiteSpace(req.Body)) return Results.BadRequest(new { error = "Message cannot be empty." });

    var msg = new ChatMessage
    {
        GroupId = groupId,
        SenderUserId = caller.Id,
        SenderName = caller.Name,
        Body = req.Body.Trim(),
        CreatedAt = DateTime.UtcNow
    };
    db.ChatMessages.Add(msg);
    await db.SaveChangesAsync();
    return Results.Created($"/api/chat/{groupId}/{msg.Id}", msg);
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

public class Group
{
    public int      Id              { get; set; }
    [Required] public string Name  { get; set; } = string.Empty;
    public string   Description     { get; set; } = string.Empty;
    public int      CreatedByUserId { get; set; }
    public DateTime CreatedAt       { get; set; } = DateTime.UtcNow;
}

public class GroupMember
{
    public int       Id       { get; set; }
    public int       GroupId  { get; set; }
    public int       UserId   { get; set; }
    public string    Status   { get; set; } = "pending"; // pending | accepted | declined
    public DateTime? JoinedAt { get; set; }
}

public class Notification
{
    public int      Id        { get; set; }
    public int      UserId    { get; set; }
    public string   Type      { get; set; } = string.Empty;
    public string   Title     { get; set; } = string.Empty;
    public string   Body      { get; set; } = string.Empty;
    public string?  Payload   { get; set; }
    public bool     IsRead    { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

public class ChatMessage
{
    public int      Id           { get; set; }
    public int      GroupId      { get; set; }
    public int      SenderUserId { get; set; }
    public string   SenderName   { get; set; } = string.Empty;
    public string   Body         { get; set; } = string.Empty;
    public DateTime CreatedAt    { get; set; } = DateTime.UtcNow;
}

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<AppUser>     Users         => Set<AppUser>();
    public DbSet<TaskItem>    Tasks         => Set<TaskItem>();
    public DbSet<Group>       Groups        => Set<Group>();
    public DbSet<GroupMember> GroupMembers  => Set<GroupMember>();
    public DbSet<Notification> Notifications => Set<Notification>();
    public DbSet<ChatMessage> ChatMessages  => Set<ChatMessage>();
}

// ── REQUEST DTOs ──────────────────────────────────────────────────────────────
public record LoginRequest(string Username, string Password);
public record CreateUserRequest(string Username, string Password, string? Name, string? Email, string? Role, string? EmployeeId);
public record UpdateUserRequest(string? Name, string? Email, string? Password, string? Role, string? EmployeeId);
public record CreateGroupRequest(string Name, string? Description);
public record InviteRequest(List<int> UserIds);
public record RespondRequest(string Action, int? NotificationId);
public record BulkTaskRequest(string Title, string? Description, string? Priority, string? Category, DateTime? DueDate, List<int> UserIds);
public record SendMessageRequest(string Body);