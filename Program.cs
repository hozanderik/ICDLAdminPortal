using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRouting();
builder.Services.AddDirectoryBrowser();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GetSecret()))
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OwnerOnly", policy => policy.RequireClaim("role", "Owner"));
    options.AddPolicy("DistributorOnly", policy => policy.RequireClaim("role", "Distributor"));
    options.AddPolicy("StudentOnly", policy => policy.RequireClaim("role", "Student"));
});

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseDirectoryBrowser();
app.UseAuthentication();
app.UseAuthorization();

var usersEnv = Environment.GetEnvironmentVariable("ICDL_USERS_FILE");
string usersFile = usersEnv ?? (OperatingSystem.IsWindows() ? @"C:\ICDL_Exam\Credits\users.json" : Path.Combine(AppContext.BaseDirectory, "users.json"));
var usersDir = Path.GetDirectoryName(usersFile);
if (!string.IsNullOrEmpty(usersDir)) Directory.CreateDirectory(usersDir);
if (!File.Exists(usersFile)) File.WriteAllText(usersFile, "[]");

List<UserAccount> LoadUsers()
{
    try
    {
        var json = File.ReadAllText(usersFile);
        var list = JsonSerializer.Deserialize<List<UserAccount>>(json) ?? new List<UserAccount>();
        bool migrated = false;

        if (list.Count == 0)
        {
            list.Add(new UserAccount 
            { 
                Username = "admin", 
                Password = "admin", 
                Role = "Owner", 
                UnlimitedBalance = true, 
                IsAdmin = true 
            });
            migrated = true;
        }

        foreach (var u in list)
        {
            if (string.IsNullOrEmpty(u.Role) || (u.Role == "Student" && (u.IsAdmin || string.Equals(u.Username, "admin", StringComparison.OrdinalIgnoreCase))))
            {
                if (string.Equals(u.Username, "admin", StringComparison.OrdinalIgnoreCase))
                {
                    u.Role = "Owner";
                    u.UnlimitedBalance = true;
                    u.Parent = null;
                }
                else if (u.IsAdmin)
                {
                    u.Role = "Distributor";
                    u.UnlimitedBalance = false;
                    if (string.IsNullOrEmpty(u.Parent)) u.Parent = "admin";
                }
                else
                {
                    u.Role = "Student";
                    u.UnlimitedBalance = false;
                    if (string.IsNullOrEmpty(u.Parent)) u.Parent = "admin";
                }
                migrated = true;
            }
        }
        if (migrated) SaveUsers(list);
        return list;
    }
    catch (Exception ex) 
    { 
        Console.WriteLine($"Error loading users: {ex}");
        return new List<UserAccount>(); 
    }
}

void SaveUsers(List<UserAccount> users)
{
    var json = JsonSerializer.Serialize(users, new JsonSerializerOptions{WriteIndented = true});
    File.WriteAllText(usersFile, json);
}

static string GetSecret()
{
    var s = Environment.GetEnvironmentVariable("ICDL_ADMIN_SECRET");
    return string.IsNullOrWhiteSpace(s) ? "dev_secret_1234567890" : s;
}

static string? GetCurrentUser(HttpContext ctx)
{
    var nameClaim = ctx.User?.Claims?.FirstOrDefault(c => c.Type == "name")?.Value;
    var fallbackName = ctx.User?.Identity?.Name;
    return nameClaim ?? fallbackName;
}

static string IssueToken(UserAccount user)
{
    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(GetSecret()));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var claims = new List<System.Security.Claims.Claim>
    {
        new("name", user.Username),
        new("role", user.Role)
    };
    var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddHours(12),
        signingCredentials: creds
    );
    return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
}

UserAccount? Authenticate(string username, string password)
{
    var users = LoadUsers();
    return users.FirstOrDefault(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase) && u.Password == password);
}

List<UserAccount> GetVisible(string current)
{
    var users = LoadUsers();
    var me = users.FirstOrDefault(u => string.Equals(u.Username, current, StringComparison.OrdinalIgnoreCase));
    if (me == null) return new List<UserAccount>();
    if (me.Role == "Owner") return users;
    if (me.Role == "Distributor") return users.Where(u => string.Equals(u.Parent, current, StringComparison.OrdinalIgnoreCase)).ToList();
    return users.Where(u => string.Equals(u.Username, current, StringComparison.OrdinalIgnoreCase)).ToList();
}

bool CreateDistributor(string owner, string username, string password, int balance)
{
    var users = LoadUsers();
    var me = users.FirstOrDefault(u => string.Equals(u.Username, owner, StringComparison.OrdinalIgnoreCase));
    if (me == null || me.Role != "Owner") return false;
    if (users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase))) return false;
    if (!me.UnlimitedBalance && me.Balance < balance) return false;
    if (!me.UnlimitedBalance) me.Balance -= balance;
    users.Add(new UserAccount{ Username = username, Password = password, Role = "Distributor", Parent = owner, Balance = balance, UnlimitedBalance = false, IsAdmin = true });
    SaveUsers(users);
    return true;
}

bool CreateStudent(string distributor, string username, string password, int balance)
{
    var users = LoadUsers();
    var dist = users.FirstOrDefault(u => string.Equals(u.Username, distributor, StringComparison.OrdinalIgnoreCase));
    if (dist == null || (dist.Role != "Distributor" && dist.Role != "Owner")) return false;
    if (users.Any(u => string.Equals(u.Username, username, StringComparison.OrdinalIgnoreCase))) return false;
    if (!dist.UnlimitedBalance && dist.Balance < balance) return false;
    if (!dist.UnlimitedBalance) dist.Balance -= balance;
    users.Add(new UserAccount{ Username = username, Password = password, Role = "Student", Parent = distributor, Balance = balance, UnlimitedBalance = false, IsAdmin = false });
    SaveUsers(users);
    return true;
}

bool UpdatePassword(string current, string targetUsername, string newPassword)
{
    var users = LoadUsers();
    var me = users.FirstOrDefault(u => string.Equals(u.Username, current, StringComparison.OrdinalIgnoreCase));
    if (me == null) return false;
    var target = users.FirstOrDefault(u => string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
    if (target == null) return false;
    if (me.Role == "Owner" && target.Role == "Distributor") { target.Password = newPassword; SaveUsers(users); return true; }
    if (me.Role == "Distributor" && target.Role == "Student" && string.Equals(target.Parent, current, StringComparison.OrdinalIgnoreCase)) { target.Password = newPassword; SaveUsers(users); return true; }
    return false;
}

bool UpdateBalance(string current, string targetUsername, int newBalance)
{
    var users = LoadUsers();
    var me = users.FirstOrDefault(u => string.Equals(u.Username, current, StringComparison.OrdinalIgnoreCase));
    var target = users.FirstOrDefault(u => string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
    if (me == null || target == null) return false;
    int delta = newBalance - target.Balance;
    if (delta > 0)
    {
        if (!me.UnlimitedBalance && me.Balance < delta) return false;
        if (!me.UnlimitedBalance) me.Balance -= delta;
    }
    target.Balance = newBalance;
    SaveUsers(users);
    return true;
}

bool UpdateUsername(string current, string targetUsername, string newUsername)
{
    var users = LoadUsers();
    var me = users.FirstOrDefault(u => string.Equals(u.Username, current, StringComparison.OrdinalIgnoreCase));
    if (me == null) return false;
    var target = users.FirstOrDefault(u => string.Equals(u.Username, targetUsername, StringComparison.OrdinalIgnoreCase));
    if (target == null) return false;
    if (users.Any(u => string.Equals(u.Username, newUsername, StringComparison.OrdinalIgnoreCase))) return false;

    if (me.Role == "Owner" && target.Role == "Distributor")
    {
        var old = target.Username;
        target.Username = newUsername;
        foreach (var u in users.Where(u => string.Equals(u.Parent, old, StringComparison.OrdinalIgnoreCase)))
        {
            u.Parent = newUsername;
        }
        SaveUsers(users);
        return true;
    }
    if (me.Role == "Distributor" && target.Role == "Student" && string.Equals(target.Parent, current, StringComparison.OrdinalIgnoreCase))
    {
        target.Username = newUsername;
        SaveUsers(users);
        return true;
    }
    return false;
}

app.MapGet("/api/health", () => Results.Ok("API is running"));

app.MapPost("/api/auth/login", (LoginRequest req) => {
    var user = Authenticate(req.Username, req.Password);
    if (user == null) return Results.Unauthorized();
    var token = IssueToken(user);
    return Results.Json(new { token, username = user.Username, role = user.Role });
});

app.MapGet("/api/users", (HttpContext ctx, string? current) => {
    var fromToken = GetCurrentUser(ctx);
    var name = string.IsNullOrEmpty(fromToken) ? (current ?? "") : fromToken;
    return Results.Json(GetVisible(name));
}).RequireAuthorization();

app.MapPost("/api/owner/distributors", (HttpContext ctx, CreateUserRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return CreateDistributor(name, req.Username, req.Password, req.Balance) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("OwnerOnly");

app.MapPut("/api/owner/distributors/password", (HttpContext ctx, UpdateUserPasswordRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdatePassword(name, req.Target, req.NewPassword) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("OwnerOnly");

app.MapPost("/api/distributor/students", (HttpContext ctx, CreateUserRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return CreateStudent(name, req.Username, req.Password, req.Balance) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("DistributorOnly");

app.MapPut("/api/distributor/students/password", (HttpContext ctx, UpdateUserPasswordRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdatePassword(name, req.Target, req.NewPassword) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("DistributorOnly");

app.MapPut("/api/distributor/students/balance", (HttpContext ctx, UpdateUserBalanceRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdateBalance(name, req.Target, req.NewBalance) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("DistributorOnly");

app.MapPut("/api/owner/distributors/balance", (HttpContext ctx, UpdateUserBalanceRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdateBalance(name, req.Target, req.NewBalance) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("OwnerOnly");

app.MapPut("/api/owner/distributors/username", (HttpContext ctx, UpdateUserUsernameRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdateUsername(name, req.Target, req.NewUsername) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("OwnerOnly");

app.MapPut("/api/distributor/students/username", (HttpContext ctx, UpdateUserUsernameRequest req) => {
    var name = GetCurrentUser(ctx) ?? "";
    return UpdateUsername(name, req.Target, req.NewUsername) ? Results.Ok() : Results.BadRequest();
}).RequireAuthorization("DistributorOnly");

app.MapPost("/api/credits/deduct", (HttpContext ctx) => {
    var name = GetCurrentUser(ctx) ?? "";
    var users = LoadUsers();
    var user = users.FirstOrDefault(u => string.Equals(u.Username, name, StringComparison.OrdinalIgnoreCase));
    if (user == null) return Results.BadRequest();
    if (user.UnlimitedBalance) return Results.Ok();
    if (user.Balance <= 0) return Results.BadRequest();
    user.Balance -= 1;
    SaveUsers(users);
    return Results.Ok();
}).RequireAuthorization("StudentOnly");

app.Run();

public class UserAccount
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public int Balance { get; set; }
    public bool IsAdmin { get; set; }
    public string Role { get; set; } = "Student";
    public string? Parent { get; set; }
    public bool UnlimitedBalance { get; set; }
}

public record LoginRequest(string Username, string Password);
public record CreateUserRequest(string Username, string Password, int Balance);
public record UpdateUserPasswordRequest(string Target, string NewPassword);
public record UpdateUserBalanceRequest(string Target, int NewBalance);
public record UpdateUserUsernameRequest(string Target, string NewUsername);
