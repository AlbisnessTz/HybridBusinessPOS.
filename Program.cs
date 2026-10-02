using Microsoft.Data.Sqlite;
using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

var dbPath = Path.Combine(builder.Environment.ContentRootPath, "sheehan_lights.db");

builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/forbidden";
        options.Cookie.Name = "SheehanLights.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
            ? CookieSecurePolicy.SameAsRequest
            : CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();
var app = builder.Build();

var loginThrottle = new ConcurrentDictionary<string, LoginAttemptState>();
var httpContextAccessor = app.Services.GetRequiredService<IHttpContextAccessor>();

app.UseStaticFiles();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var path = context.Request.Path;

    if ((HttpMethods.IsPost(context.Request.Method) ||
         HttpMethods.IsPut(context.Request.Method) ||
         HttpMethods.IsPatch(context.Request.Method) ||
         HttpMethods.IsDelete(context.Request.Method)) &&
        !path.StartsWithSegments("/login") &&
        !path.StartsWithSegments("/forbidden"))
    {
        if (!IsSameOriginRequest(context))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new { message = "Cross-site request blocked." });
            return;
        }
    }

    await next();
});

app.Use(async (context, next) =>
{
    var path = context.Request.Path;

    if (path.StartsWithSegments("/login") ||
        path.StartsWithSegments("/forbidden"))
    {
        await next();
        return;
    }

    if (context.User.Identity?.IsAuthenticated != true)
    {
        if (path.StartsWithSegments("/api"))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { message = "Authentication required." });
            return;
        }

        var returnUrl = context.Request.PathBase + context.Request.Path + context.Request.QueryString;
        context.Response.Redirect("/login?returnUrl=" + Uri.EscapeDataString(returnUrl));
        return;
    }

    var userIdValue = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!int.TryParse(userIdValue, out var authenticatedUserId))
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        context.Response.Redirect("/login?error=Please%20sign%20in%20again");
        return;
    }

    var currentUser = await FindUserById(authenticatedUserId);
    if (currentUser is null || !currentUser.Active)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        context.Response.Redirect("/login?error=This%20account%20is%20disabled");
        return;
    }

    if (context.User.FindFirstValue("must_change_password") == "1" &&
        !path.StartsWithSegments("/account") &&
        !path.StartsWithSegments("/logout"))
    {
        context.Response.Redirect("/account?change=1");
        return;
    }

    await next();
});

InitializeDatabase();
CreateAutomaticBackup();
string ConnectionString() => $"Data Source={dbPath}";

app.MapGet("/", async (HttpContext context) =>
{
    var isOwner = context.User.IsInRole("Owner");
    return Html("Dashboard", await DashboardPage(isOwner), "home");
});

app.MapGet("/login", (HttpRequest request, HttpContext context) =>
{
    if (context.User.Identity?.IsAuthenticated == true)
        return Results.Redirect("/");

    var error = request.Query["error"].ToString();
    return Results.Content(LoginPage(error), "text/html");
});

app.MapPost("/login", async (HttpRequest request, HttpContext context) =>
{
    var clientKey = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!AllowLoginAttempt(clientKey))
        return Results.Redirect("/login?error=Too%20many%20login%20attempts.%20Please%20wait%20a%20few%20minutes");

    var form = await request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();

    var user = await FindUser(username);

    if (user is null)
    {
        RegisterFailedLoginAttempt(clientKey);
        return Results.Redirect("/login?error=Invalid%20username%20or%20password");
    }

    if (user.LockedUntil.HasValue && user.LockedUntil.Value > DateTimeOffset.UtcNow)
    {
        RegisterFailedLoginAttempt(clientKey);
        return Results.Redirect("/login?error=Account%20temporarily%20locked%20after%20too%20many%20failed%20attempts");
    }

    if (!user.Active)
    {
        RegisterFailedLoginAttempt(clientKey);
        return Results.Redirect("/login?error=This%20account%20is%20disabled");
    }

    if (!VerifyPassword(password, user.PasswordHash))
    {
        RegisterFailedLoginAttempt(clientKey);
        var nextFailed = user.FailedAttempts + 1;
        var lockedUntil = nextFailed >= 5
            ? DateTimeOffset.UtcNow.AddMinutes(10).ToString("O")
            : null;

        await ExecuteAsync(
            "UPDATE users SET failed_attempts=$failed,locked_until=$locked WHERE id=$id",
            command =>
            {
                Add(command, "$failed", nextFailed >= 5 ? 0 : nextFailed);
                Add(command, "$locked", (object?)lockedUntil ?? DBNull.Value);
                Add(command, "$id", user.Id);
            });

        return Results.Redirect("/login?error=Invalid%20username%20or%20password");
    }

    await ExecuteAsync(
        "UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=$id",
        command => Add(command, "$id", user.Id));

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(ClaimTypes.Name, user.Username),
        new(ClaimTypes.Role, user.Role),
        new("must_change_password", user.MustChangePassword ? "1" : "0")
    };

    var identity = new ClaimsIdentity(
        claims,
        CookieAuthenticationDefaults.AuthenticationScheme);

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    ClearLoginAttempts(clientKey);

    var returnUrl = form["returnUrl"].ToString();
    return string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith("/")
        ? Results.Redirect("/")
        : Results.Redirect(returnUrl);
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.MapGet("/forbidden", () => Results.Content(
    LoginPage("You do not have permission to access that area."),
    "text/html"));

app.MapGet("/products", async (HttpContext context) =>
{
    return Html("Products", await ProductsPage(context.User.IsInRole("Owner")), "products");
});

app.MapPost("/products", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var name = form["name"].ToString().Trim();

    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest("Product name is required.");

    await ExecuteAsync(
        @"INSERT INTO products
          (name, sku, category, buying_price, selling_price, stock_qty, low_stock_level, created_at)
          VALUES($name,$sku,$category,$buying,$selling,$stock,$low,$created)",
        command =>
        {
            Add(command, "$name", name);
            Add(command, "$sku", form["sku"].ToString().Trim());
            Add(command, "$category",
                string.IsNullOrWhiteSpace(form["category"])
                    ? "General"
                    : form["category"].ToString().Trim());
            Add(command, "$buying", ParseFormMoney(form["buying_price"]));
            Add(command, "$selling", ParseFormMoney(form["selling_price"]));
            Add(command, "$stock", Math.Max(0, ParseFormInt(form["stock_qty"])));
            Add(command, "$low", Math.Max(1, ParseFormInt(form["low_stock_level"], 5)));
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
        });

    var createdProductId = (await QueryAsync(
        "SELECT id FROM products WHERE name=$name ORDER BY id DESC LIMIT 1",
        command => Add(command, "$name", name)))[0]["id"];

    await AuditAsync(
        "Created Product",
        "Product",
        Convert.ToInt32(createdProductId),
        $"Created {name} with opening stock {ParseFormInt(form["stock_qty"])}");

    return Results.Redirect("/products?saved=1");
});

app.MapPost("/products/adjust", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var productId = ParseFormInt(form["product_id"]);
    var quantity = ParseFormInt(form["quantity"]);
    var mode = form["mode"].ToString().Trim().ToLowerInvariant();

    if (productId <= 0 || quantity <= 0 || (mode != "in" && mode != "out"))
        return Results.BadRequest("Invalid stock adjustment.");

    var productRows = await QueryAsync(
        "SELECT name,stock_qty FROM products WHERE id=$id",
        command => Add(command, "$id", productId));

    if (productRows.Count == 0)
        return Results.NotFound("Product not found.");

    var productName = productRows[0]["name"]?.ToString() ?? "Product";
    var oldStock = Convert.ToInt32(productRows[0]["stock_qty"]);
    var delta = mode == "out" ? -quantity : quantity;
    var newStock = Math.Max(0, oldStock + delta);

    await ExecuteAsync(
        "UPDATE products SET stock_qty = $stock WHERE id = $id",
        command =>
        {
            Add(command, "$stock", newStock);
            Add(command, "$id", productId);
        });

    await AuditAsync(
        "Stock Adjustment",
        "Product",
        productId,
        $"{mode.ToUpperInvariant()} {quantity} units of {productName}; stock {oldStock} -> {newStock}");

    return Results.Redirect("/products?stock=1");
});

app.MapPost("/products/delete", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var id = ParseFormInt(form["id"]);

    if (id > 0)
        await ExecuteAsync(
            "DELETE FROM products WHERE id=$id",
            command => Add(command, "$id", id));

    return Results.Redirect("/products");
});

app.MapGet("/customers", async () => Html("Customers", await CustomersPage(), "customers"));

app.MapPost("/customers", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var name = form["name"].ToString().Trim();

    if (string.IsNullOrWhiteSpace(name))
        return Results.BadRequest("Customer name is required.");

    await ExecuteAsync(
        "INSERT INTO customers(name,phone,address,created_at) VALUES($name,$phone,$address,$created)",
        command =>
        {
            Add(command, "$name", name);
            Add(command, "$phone", form["phone"].ToString().Trim());
            Add(command, "$address", form["address"].ToString().Trim());
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
        });

    return Results.Redirect("/customers?saved=1");
});

app.MapGet("/daily-closing", async () =>
{
    return Html("Daily Closing", await DailyClosingPage(), "daily");
});

app.MapPost("/daily-closing/expense", async (HttpRequest request, HttpContext context) =>
{
    if (!context.User.IsInRole("Owner") && !context.User.IsInRole("Employee"))
        return Results.Forbid();

    var today = DateTime.Today.ToString("yyyy-MM-dd");
    var closed = await QueryAsync(
        "SELECT id FROM daily_closings WHERE business_date=$date LIMIT 1",
        command => Add(command, "$date", today));

    if (closed.Count > 0)
        return Results.Redirect("/daily-closing?error=Today%20is%20already%20closed");

    var form = await request.ReadFormAsync();
    var category = string.IsNullOrWhiteSpace(form["category"]) ? "General" : form["category"].ToString().Trim();
    var description = form["description"].ToString().Trim();
    var amount = ParseFormMoney(form["amount"]);

    if (amount <= 0)
        return Results.Redirect("/daily-closing?error=Expense%20amount%20must%20be%20greater%20than%20zero");

    var userId = int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedId) ? parsedId : 0;
    var username = context.User.Identity?.Name ?? "User";

    await ExecuteAsync(
        @"INSERT INTO expenses
          (category,description,amount,expense_date,created_at,recorded_by_user_id,recorded_by_username)
          VALUES($category,$description,$amount,$date,$created,$user_id,$username)",
        command =>
        {
            Add(command, "$category", category);
            Add(command, "$description", description);
            Add(command, "$amount", amount);
            Add(command, "$date", today);
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
            Add(command, "$user_id", userId > 0 ? userId : DBNull.Value);
            Add(command, "$username", username);
        });

    await AuditAsync("Recorded Daily Expense", "Expense", null,
        $"{today} · {category}: {Money(amount)}{(string.IsNullOrWhiteSpace(description) ? "" : " — " + description)}");

    return Results.Redirect("/daily-closing?saved=1");
});

app.MapPost("/daily-closing/close", async (HttpRequest request, HttpContext context) =>
{
    if (!context.User.IsInRole("Owner") && !context.User.IsInRole("Employee"))
        return Results.Forbid();

    var today = DateTime.Today.ToString("yyyy-MM-dd");
    var existing = await QueryAsync(
        "SELECT id FROM daily_closings WHERE business_date=$date LIMIT 1",
        command => Add(command, "$date", today));

    if (existing.Count > 0)
        return Results.Redirect("/daily-closing?error=Today%20is%20already%20closed");

    var (startUtc, endUtc) = LocalDayUtcRange(DateTime.Today);

    var sales = (await QueryAsync(
        @"SELECT COALESCE(SUM(total),0) total,COUNT(*) count
          FROM sales WHERE created_at >= $start AND created_at < $end",
        command =>
        {
            Add(command, "$start", startUtc);
            Add(command, "$end", endUtc);
        }))[0];

    var expenses = (await QueryAsync(
        "SELECT COALESCE(SUM(amount),0) total FROM expenses WHERE expense_date=$date",
        command => Add(command, "$date", today)))[0];

    var totalSales = Convert.ToDouble(sales["total"] ?? 0);
    var count = Convert.ToInt32(sales["count"] ?? 0);
    var totalExpenses = Convert.ToDouble(expenses["total"] ?? 0);
    var paymentRows = await QueryAsync(
        @"SELECT payment_method,COALESCE(SUM(total),0) total
          FROM sales
          WHERE created_at >= $start AND created_at < $end
          GROUP BY payment_method",
        command =>
        {
            Add(command, "$start", startUtc);
            Add(command, "$end", endUtc);
        });

    var closeForm = await request.ReadFormAsync();
    var actualCash = Math.Max(0, ParseFormMoney(closeForm["actual_cash"]));
    var actualMpesa = Math.Max(0, ParseFormMoney(closeForm["actual_mpesa"]));
    var actualCard = Math.Max(0, ParseFormMoney(closeForm["actual_card"]));
    var actualBank = Math.Max(0, ParseFormMoney(closeForm["actual_bank"]));

    var userId = int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedId) ? parsedId : 0;
    var username = context.User.Identity?.Name ?? "User";
    var notes = closeForm["notes"].ToString().Trim();

    await ExecuteAsync(
        @"INSERT INTO daily_closings
          (business_date,closed_by_user_id,closed_by_username,total_sales,transaction_count,total_expenses,
           actual_cash,actual_mpesa,actual_card,actual_bank,notes,closed_at)
          VALUES($date,$user_id,$username,$sales,$count,$expenses,$actual_cash,$actual_mpesa,$actual_card,$actual_bank,$notes,$closed_at)",
        command =>
        {
            Add(command, "$date", today);
            Add(command, "$user_id", userId > 0 ? userId : DBNull.Value);
            Add(command, "$username", username);
            Add(command, "$sales", totalSales);
            Add(command, "$count", count);
            Add(command, "$expenses", totalExpenses);
            Add(command, "$actual_cash", actualCash);
            Add(command, "$actual_mpesa", actualMpesa);
            Add(command, "$actual_card", actualCard);
            Add(command, "$actual_bank", actualBank);
            Add(command, "$notes", notes);
            Add(command, "$closed_at", DateTime.UtcNow.ToString("O"));
        });

    await AuditAsync("Closed Daily Sales", "Daily Closing", null,
        $"{today} · sales {Money(totalSales)} · transactions {count} · expenses {Money(totalExpenses)}");

    return Results.Redirect("/daily-closing?closed=1");
});

app.MapPost("/daily-closing/reopen", async (HttpContext context) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    var today = DateTime.Today.ToString("yyyy-MM-dd");
    await ExecuteAsync(
        "DELETE FROM daily_closings WHERE business_date=$date",
        command => Add(command, "$date", today));

    await AuditAsync("Reopened Daily Sales", "Daily Closing", null,
        $"{today} · daily closing reopened by owner");

    return Results.Redirect("/daily-closing?reopened=1");
});

app.MapGet("/expenses", async (HttpContext context) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    return Html("Expenses", await ExpensesPage(), "expenses");
});

app.MapPost("/expenses", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var today = DateTime.Today.ToString("yyyy-MM-dd");
    var closedRows = await QueryAsync(
        "SELECT id FROM daily_closings WHERE business_date=$date LIMIT 1",
        command => Add(command, "$date", today));

    if (closedRows.Count > 0)
        return Results.Redirect("/expenses?error=Today%20is%20already%20closed");

    var form = await request.ReadFormAsync();
    var category = string.IsNullOrWhiteSpace(form["category"])
        ? "General"
        : form["category"].ToString().Trim();
    var description = form["description"].ToString().Trim();
    var amount = ParseFormMoney(form["amount"]);

    if (amount <= 0)
        return Results.BadRequest("Expense amount must be greater than zero.");

    var userId = int.TryParse(request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedId) ? parsedId : 0;
    var username = request.HttpContext.User.Identity?.Name ?? "Owner";

    await ExecuteAsync(
        @"INSERT INTO expenses
          (category,description,amount,expense_date,created_at,recorded_by_user_id,recorded_by_username)
          VALUES($category,$description,$amount,$date,$created,$user_id,$username)",
        command =>
        {
            Add(command, "$category", category);
            Add(command, "$description", description);
            Add(command, "$amount", amount);
            Add(command, "$date", today);
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
            Add(command, "$user_id", userId > 0 ? userId : DBNull.Value);
            Add(command, "$username", username);
        });

    await AuditAsync(
        "Recorded Expense",
        "Expense",
        null,
        $"{category}: {Money(amount)}{(string.IsNullOrWhiteSpace(description) ? "" : " — " + description)}");

    return Results.Redirect("/expenses?saved=1");
});

app.MapGet("/sales", async () => Html("New Sale", await SalesPage(), "sales"));

app.MapGet("/api/products", async () =>
{
    var rows = await QueryAsync(
        "SELECT id,name,category,selling_price,stock_qty FROM products WHERE stock_qty > 0 ORDER BY name");

    return Results.Json(rows.Select(row => new
    {
        id = Convert.ToInt32(row["id"]),
        name = row["name"]?.ToString(),
        category = row["category"]?.ToString(),
        price = Convert.ToDouble(row["selling_price"]),
        stock = Convert.ToInt32(row["stock_qty"])
    }));
});

app.MapGet("/api/customers", async () =>
{
    var rows = await QueryAsync(
        "SELECT id,name,phone FROM customers ORDER BY name");

    return Results.Json(rows.Select(row => new
    {
        id = Convert.ToInt32(row["id"]),
        name = row["name"]?.ToString(),
        phone = row["phone"]?.ToString()
    }));
});

app.MapPost("/api/checkout", async (HttpRequest request) =>
{
    var input = await System.Text.Json.JsonSerializer.DeserializeAsync<CheckoutRequest>(
        request.Body,
        new System.Text.Json.JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        });

    if (input is null || input.Items is null || input.Items.Count == 0)
        return Results.BadRequest(new { message = "Add at least one product." });

    var todayBusinessDate = DateTime.Today.ToString("yyyy-MM-dd");
    var dailyClosed = await QueryAsync(
        "SELECT id FROM daily_closings WHERE business_date=$date LIMIT 1",
        command => Add(command, "$date", todayBusinessDate));

    if (dailyClosed.Count > 0)
        return Results.BadRequest(new { message = "Today's sales are already closed. Ask the Owner to reopen the day before making another sale." });

    var paymentMethod = string.IsNullOrWhiteSpace(input.PaymentMethod)
        ? "Cash"
        : input.PaymentMethod.Trim();
    var paymentReference = input.PaymentReference?.Trim();

    if (paymentMethod == "M-Pesa" && string.IsNullOrWhiteSpace(paymentReference))
        return Results.BadRequest(new { message = "Enter the M-Pesa transaction reference before completing this sale." });

    await using var connection = new SqliteConnection(ConnectionString());
    await connection.OpenAsync();
    await using var transaction = connection.BeginTransaction();

    try
    {
        var lines = new List<CheckoutLine>();
        double subtotal = 0;

        foreach (var item in input.Items)
        {
            if (item.ProductId <= 0 || item.Quantity <= 0)
                throw new InvalidOperationException("Invalid product or quantity.");

            var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText =
                "SELECT id,name,buying_price,selling_price,stock_qty FROM products WHERE id=$id";
            Add(command, "$id", item.ProductId);

            await using var reader = await command.ExecuteReaderAsync();

            if (!await reader.ReadAsync())
                throw new InvalidOperationException("Product not found.");

            var productId = reader.GetInt32(0);
            var productName = reader.GetString(1);
            var buyingPrice = reader.GetDouble(2);
            var sellingPrice = reader.GetDouble(3);
            var stock = reader.GetInt32(4);

            if (item.Quantity > stock)
                throw new InvalidOperationException(
                    $"Not enough stock for {productName}. Available: {stock}.");

            var lineTotal = sellingPrice * item.Quantity;
            subtotal += lineTotal;

            lines.Add(new CheckoutLine(
                productId,
                productName,
                item.Quantity,
                buyingPrice,
                sellingPrice,
                lineTotal));
        }

        var discount = Math.Clamp(input.Discount, 0, subtotal);
        var total = subtotal - discount;
        var invoice = "SL-" + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");

        var saleCommand = connection.CreateCommand();
        saleCommand.Transaction = transaction;
        saleCommand.CommandText = @"
            INSERT INTO sales
            (invoice_no,customer_id,subtotal,discount,total,payment_method,payment_reference,created_at)
            VALUES($invoice,$customer,$subtotal,$discount,$total,$payment,$reference,$created)
            RETURNING id";

        Add(saleCommand, "$invoice", invoice);
        Add(saleCommand, "$customer",
            input.CustomerId.HasValue ? (object)input.CustomerId.Value : DBNull.Value);
        Add(saleCommand, "$subtotal", subtotal);
        Add(saleCommand, "$discount", discount);
        Add(saleCommand, "$total", total);
        Add(saleCommand, "$payment", paymentMethod);
        Add(saleCommand, "$reference",
            string.IsNullOrWhiteSpace(paymentReference)
                ? DBNull.Value
                : paymentReference);
        Add(saleCommand, "$created", DateTime.UtcNow.ToString("O"));

        var saleId = Convert.ToInt64(await saleCommand.ExecuteScalarAsync());

        foreach (var line in lines)
        {
            var lineCommand = connection.CreateCommand();
            lineCommand.Transaction = transaction;
            lineCommand.CommandText = @"
                INSERT INTO sale_items
                (sale_id,product_id,quantity,unit_price,buying_price,line_total)
                VALUES($sale,$product,$quantity,$unit,$buying,$line)";

            Add(lineCommand, "$sale", saleId);
            Add(lineCommand, "$product", line.ProductId);
            Add(lineCommand, "$quantity", line.Quantity);
            Add(lineCommand, "$unit", line.SellingPrice);
            Add(lineCommand, "$buying", line.BuyingPrice);
            Add(lineCommand, "$line", line.LineTotal);
            await lineCommand.ExecuteNonQueryAsync();

            var stockCommand = connection.CreateCommand();
            stockCommand.Transaction = transaction;
            stockCommand.CommandText =
                "UPDATE products SET stock_qty=stock_qty-$quantity WHERE id=$product";

            Add(stockCommand, "$quantity", line.Quantity);
            Add(stockCommand, "$product", line.ProductId);
            await stockCommand.ExecuteNonQueryAsync();
        }

        transaction.Commit();

        await AuditAsync(
            "Completed Sale",
            "Sale",
            (int)saleId,
            $"Invoice {invoice}; total {Money(total)}; items {lines.Count}; payment {paymentMethod}" +
            $"{(string.IsNullOrWhiteSpace(paymentReference) ? "" : $"; reference {paymentReference}")}");

        return Results.Json(new
        {
            success = true,
            invoice,
            total,
            subtotal,
            discount,
            itemCount = lines.Count
        });
    }
    catch (Exception ex)
    {
        await transaction.RollbackAsync();
        return Results.BadRequest(new { message = ex.Message });
    }
});

app.MapGet("/receipt/{invoice}", async (string invoice) =>
{
    var rows = await QueryAsync(
        @"SELECT s.invoice_no,s.subtotal,s.discount,s.total,s.payment_method,s.payment_reference,s.created_at,
                 COALESCE(c.name,'Walk-in Customer') customer,
                 COALESCE(c.phone,'') customer_phone,
                 p.name product,si.quantity,si.unit_price,si.line_total
          FROM sales s
          LEFT JOIN customers c ON c.id=s.customer_id
          JOIN sale_items si ON si.sale_id=s.id
          JOIN products p ON p.id=si.product_id
          WHERE s.invoice_no=$invoice
          ORDER BY si.id",
        command => Add(command, "$invoice", invoice));

    if (rows.Count == 0)
        return Results.NotFound("Receipt not found.");

    var first = rows[0];
    var shop = await ShopSettings();

    var itemRows = string.Join("", rows.Select(row =>
        $@"<tr>
            <td>{E(row["product"])}</td>
            <td>{row["quantity"]}</td>
            <td>{Money(row["unit_price"])}</td>
            <td>{Money(row["line_total"])}</td>
           </tr>"));

    var shareItems = string.Join("\n", rows.Select(row =>
        $"- {row["product"]} x{row["quantity"]} = {Money(row["line_total"])}"));

    var invoiceText =
        $"{shop.Name}\n" +
        $"INVOICE: {first["invoice_no"]}\n" +
        $"Customer: {first["customer"]}\n" +
        $"Payment: {first["payment_method"]}\n\n" +
        $"{shareItems}\n\n" +
        $"Subtotal: {Money(first["subtotal"])}\n" +
        $"Discount: {Money(first["discount"])}\n" +
        $"TOTAL: {Money(first["total"])}\n\n" +
        $"Thank you for shopping with {shop.Name}.";

    var customerPhone = NormalizePhone(first["customer_phone"]?.ToString());
    var whatsappUrl = string.IsNullOrWhiteSpace(customerPhone)
        ? "https://wa.me/?text=" + WebUtility.UrlEncode(invoiceText)
        : "https://wa.me/" + customerPhone + "?text=" + WebUtility.UrlEncode(invoiceText);

    var whatsappLabel = string.IsNullOrWhiteSpace(customerPhone)
        ? "Share Invoice on WhatsApp"
        : "Send to Customer WhatsApp";

    var body = $@"
      <section class='receipt card'>
        <div class='receipt-head'>
          <div>
            <span class='eyebrow'>SALES RECEIPT</span>
            <h1>{E(shop.Name)}</h1>
            <p>{E(shop.Address)}</p>
            <p>{E(shop.Phone)}</p>
          </div>
          <div class='actions'>
            <button class='secondary' type='button' onclick='window.print()'>Print</button>
            <button class='secondary' type='button' onclick='copyInvoice(this)' data-invoice='{E(invoiceText)}'>Copy Invoice</button>
            <a class='primary' href='{E(whatsappUrl)}' target='_blank' rel='noopener'>{whatsappLabel}</a>
          </div>
        </div>

        <div class='receipt-meta'>
          <span>Invoice<strong>{E(first["invoice_no"])}</strong></span>
          <span>Customer<strong>{E(first["customer"])}</strong></span>
          <span>Payment<strong>{E(first["payment_method"])}</strong></span>
          {(string.IsNullOrWhiteSpace(first["payment_reference"]?.ToString()) ? "" : $@"<span>Reference<strong>{E(first["payment_reference"])}</strong></span>")}
        </div>

        <div class='tablewrap'>
          <table>
            <tr><th>Item</th><th>Qty</th><th>Price</th><th>Total</th></tr>
            {itemRows}
          </table>
        </div>

        <div class='receipt-total'>
          <span>Subtotal<strong>{Money(first["subtotal"])}</strong></span>
          <span>Discount<strong>{Money(first["discount"])}</strong></span>
          <span>Total<strong>{Money(first["total"])}</strong></span>
        </div>

        <p class='muted'>Thank you for shopping with {E(shop.Name)}.</p>
        <p id='invoiceCopyStatus' class='muted'></p>
      </section>

      <script>
        async function copyInvoice(button) {{
          const text = button.dataset.invoice;
          try {{
            await navigator.clipboard.writeText(text);
            document.getElementById('invoiceCopyStatus').textContent =
              'Invoice copied. Paste it into WhatsApp or another message.';
            button.textContent = 'Copied';
            setTimeout(() => button.textContent = 'Copy Invoice', 2000);
          }} catch {{
            window.prompt('Copy this invoice and paste it into WhatsApp:', text);
          }}
        }}
      </script>";

    return Html("Receipt", body, "sales");
});

app.MapGet("/account", async (HttpRequest request) =>
{
    var forceChange = request.Query["change"] == "1";
    return Html("Account", await AccountPage(forceChange), "account");
});

app.MapPost("/account/password", async (HttpRequest request, HttpContext context) =>
{
    var form = await request.ReadFormAsync();
    var currentPassword = form["current_password"].ToString();
    var newPassword = form["new_password"].ToString();
    var confirmPassword = form["confirm_password"].ToString();

    if (newPassword.Length < 12 || newPassword != confirmPassword)
        return Results.Redirect("/account?error=Use%20a%20matching%20password%20of%20at%20least%2012%20characters");

    var userId = int.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedId)
        ? parsedId
        : 0;

    var user = await FindUserById(userId);
    if (user is null || !VerifyPassword(currentPassword, user.PasswordHash))
        return Results.Redirect("/account?error=Current%20password%20is%20incorrect");

    await ExecuteAsync(
        "UPDATE users SET password_hash=$hash,must_change_password=0,failed_attempts=0,locked_until=NULL WHERE id=$id",
        command =>
        {
            Add(command, "$hash", HashPassword(newPassword));
            Add(command, "$id", user.Id);
        });

    var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(ClaimTypes.Name, user.Username),
        new(ClaimTypes.Role, user.Role),
        new("must_change_password", "0")
    };

    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(
            claims,
            CookieAuthenticationDefaults.AuthenticationScheme)));

    return Results.Redirect("/account?saved=1");
});

app.MapGet("/staff", async (HttpContext context, HttpRequest request) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    return Html("Staff", await StaffPage(request), "staff");
});

app.MapPost("/staff", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();

    if (username.Length < 3 || username.Length > 32 || username.Any(char.IsWhiteSpace))
        return Results.Redirect("/staff?error=Username%20must%20be%203-32%20characters%20without%20spaces");

    if (password.Length < 12)
        return Results.Redirect("/staff?error=Temporary%20password%20must%20be%20at%20least%2012%20characters");

    if (await FindUser(username) is not null)
        return Results.Redirect("/staff?error=That%20username%20already%20exists");

    await ExecuteAsync(
        @"INSERT INTO users
          (username,password_hash,role,active,must_change_password,failed_attempts,created_at)
          VALUES($username,$hash,'Employee',1,1,0,$created)",
        command =>
        {
            Add(command, "$username", username);
            Add(command, "$hash", HashPassword(password));
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
        });

    await AuditAsync(
        "Created Employee",
        "User",
        null,
        $"Employee account {username} created");

    return Results.Redirect("/staff?created=1");
});

app.MapPost("/staff/toggle", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var id = ParseFormInt(form["id"]);
    var currentUserId = int.TryParse(request.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedId)
        ? parsedId
        : 0;

    if (id <= 0 || id == currentUserId)
        return Results.BadRequest("Invalid staff action.");

    await ExecuteAsync(
        "UPDATE users SET active=CASE WHEN active=1 THEN 0 ELSE 1 END WHERE id=$id AND role='Employee'",
        command => Add(command, "$id", id));

    await AuditAsync(
        "Toggled Employee",
        "User",
        id,
        $"Employee account status toggled by owner");

    return Results.Redirect("/staff");
});

app.MapPost("/staff/reset-password", async (HttpRequest request, HttpContext context) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();
    var id = ParseFormInt(form["id"]);
    var password = form["password"].ToString();

    if (id <= 0 || password.Length < 12)
        return Results.Redirect("/staff?error=Reset%20password%20must%20be%20at%20least%2012%20characters");

    var user = await FindUserById(id);

    if (user is null || user.Role != "Employee")
        return Results.Redirect("/staff?error=Employee%20account%20not%20found");

    await ExecuteAsync(
        @"UPDATE users
          SET password_hash=$hash,must_change_password=1,failed_attempts=0,locked_until=NULL
          WHERE id=$id AND role='Employee'",
        command =>
        {
            Add(command, "$hash", HashPassword(password));
            Add(command, "$id", id);
        });

    await AuditAsync(
        "Reset Employee Password",
        "User",
        id,
        $"Password reset for employee {user.Username}; employee must change it on next login");

    return Results.Redirect("/staff?reset=1");
});

app.MapGet("/audit", async (HttpContext context) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    return Html("Audit Log", await AuditPage(), "audit");
});

app.MapGet("/reports", async (HttpRequest request) =>
{
    // Reports are read-only for employees. Owner-only actions remain protected
    // on their individual POST endpoints.
    return Html("Reports", await ReportsPage(request), "reports");
});

app.MapGet("/settings", async (HttpContext context) =>
{
    if (!context.User.IsInRole("Owner"))
        return Results.Forbid();

    return Html("Settings", await SettingsPage(), "settings");
});

app.MapPost("/settings", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

    var form = await request.ReadFormAsync();

    var currency = string.IsNullOrWhiteSpace(form["currency"])
        ? "TSh"
        : form["currency"].ToString().Trim();

    await ExecuteAsync(
        @"UPDATE settings
          SET shop_name=$name,
              phone=$phone,
              address=$address,
              currency=$currency,
              email=$email,
              logo_url=$logo_url,
              slogan=$slogan,
              bank_name=$bank_name,
              bank_account_number=$bank_account_number,
              bank_account_name=$bank_account_name,
              mobile_money_name=$mobile_money_name,
              mobile_money_number=$mobile_money_number,
              invoice_prefix=$invoice_prefix,
              footer_text=$footer_text
          WHERE id=1",
        command =>
        {
            Add(command, "$name", form["shop_name"].ToString().Trim());
            Add(command, "$phone", form["phone"].ToString().Trim());
            Add(command, "$address", form["address"].ToString().Trim());
            Add(command, "$currency", currency);
            Add(command, "$email", form["email"].ToString().Trim());
            Add(command, "$logo_url", form["logo_url"].ToString().Trim());
            Add(command, "$slogan", form["slogan"].ToString().Trim());
            Add(command, "$bank_name", form["bank_name"].ToString().Trim());
            Add(command, "$bank_account_number", form["bank_account_number"].ToString().Trim());
            Add(command, "$bank_account_name", form["bank_account_name"].ToString().Trim());
            Add(command, "$mobile_money_name", form["mobile_money_name"].ToString().Trim());
            Add(command, "$mobile_money_number", form["mobile_money_number"].ToString().Trim());
            Add(command, "$invoice_prefix",
                string.IsNullOrWhiteSpace(form["invoice_prefix"])
                    ? "PF-"
                    : form["invoice_prefix"].ToString().Trim());
            Add(command, "$footer_text",
                string.IsNullOrWhiteSpace(form["footer_text"])
                    ? "Thank you for your business."
                    : form["footer_text"].ToString().Trim());
        });

    await AuditAsync(
        "Updated Settings",
        "Settings",
        1,
        $"Business profile updated; currency {currency}");

    return Results.Redirect("/settings?saved=1");
});

/* First commercial-facing module: configurable, locally stored proformas. */
app.MapGet("/proforma", async () =>
    Html("New Proforma", await ProformaCreatePage(), "proforma"));

app.MapPost("/proforma", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();

    var customerName = form["customer_name"].ToString().Trim();
    if (string.IsNullOrWhiteSpace(customerName))
        return Results.BadRequest("Customer name is required.");

    var descriptions = form["item_description"].ToArray();
    var quantities = form["item_qty"].ToArray();
    var prices = form["item_price"].ToArray();

    var items = new List<(string Description, int Quantity, double UnitPrice, double LineTotal)>();

    for (var i = 0; i < descriptions.Length; i++)
    {
        var description = descriptions[i].Trim();
        var quantity = i < quantities.Length ? ParseInt(quantities[i], 0) : 0;
        var unitPrice = i < prices.Length ? ParseMoney(prices[i]) : 0d;

        if (string.IsNullOrWhiteSpace(description))
            continue;

        if (quantity <= 0 || unitPrice < 0)
            continue;

        items.Add((description, quantity, unitPrice, quantity * unitPrice));
    }

    if (items.Count == 0)
        return Results.BadRequest("Add at least one item with a valid quantity and price.");

    var subtotal = items.Sum(item => item.LineTotal);
    var discount = Math.Clamp(ParseFormMoney(form["discount"]), 0d, subtotal);
    var total = subtotal - discount;

    var shop = await ShopSettings();
    var prefix = string.IsNullOrWhiteSpace(shop.InvoicePrefix) ? "PF-" : shop.InvoicePrefix.Trim();
    var createdAt = DateTime.UtcNow.ToString("O");

    await using var connection = new SqliteConnection(ConnectionString());
    await connection.OpenAsync();
    using var transaction = connection.BeginTransaction();

    int sequence;
    await using (var nextCommand = connection.CreateCommand())
    {
        nextCommand.Transaction = transaction;
        nextCommand.CommandText = "SELECT COALESCE(MAX(id),0)+1 FROM proformas";
        sequence = Convert.ToInt32(await nextCommand.ExecuteScalarAsync());
    }

    var proformaNumber = $"{prefix}{sequence:D4}";
    long proformaId;

    await using (var insert = connection.CreateCommand())
    {
        insert.Transaction = transaction;
        insert.CommandText = @"
            INSERT INTO proformas
            (proforma_no,customer_name,customer_phone,customer_address,notes,subtotal,discount,total,created_at)
            VALUES($number,$customer,$phone,$address,$notes,$subtotal,$discount,$total,$created)";

        Add(insert, "$number", proformaNumber);
        Add(insert, "$customer", customerName);
        Add(insert, "$phone", form["customer_phone"].ToString().Trim());
        Add(insert, "$address", form["customer_address"].ToString().Trim());
        Add(insert, "$notes", form["notes"].ToString().Trim());
        Add(insert, "$subtotal", subtotal);
        Add(insert, "$discount", discount);
        Add(insert, "$total", total);
        Add(insert, "$created", createdAt);

        await insert.ExecuteNonQueryAsync();
        await using var idCommand = connection.CreateCommand();
        idCommand.Transaction = transaction;
        idCommand.CommandText = "SELECT last_insert_rowid()";
        proformaId = Convert.ToInt64(await idCommand.ExecuteScalarAsync());
    }

    foreach (var item in items)
    {
        await using var itemCommand = connection.CreateCommand();
        itemCommand.Transaction = transaction;
        itemCommand.CommandText = @"
            INSERT INTO proforma_items
            (proforma_id,description,quantity,unit_price,line_total)
            VALUES($proforma,$description,$quantity,$unit,$line)";

        Add(itemCommand, "$proforma", proformaId);
        Add(itemCommand, "$description", item.Description);
        Add(itemCommand, "$quantity", item.Quantity);
        Add(itemCommand, "$unit", item.UnitPrice);
        Add(itemCommand, "$line", item.LineTotal);
        await itemCommand.ExecuteNonQueryAsync();
    }

    await transaction.CommitAsync();
    await AuditAsync(
        "Created Proforma",
        "Proforma",
        Convert.ToInt32(proformaId),
        $"Proforma {proformaNumber}; customer {customerName}; total {Money(total)}");

    return Results.Redirect($"/proforma/{proformaId}");
});

app.MapGet("/proforma/{id:int}", async (int id) =>
    Html("Proforma", await ProformaPage(id), "proforma"));

app.Run();

async Task<string> DashboardPage(bool isOwner)
{
    var shop = await ShopSettings();
    var today = DateTime.Now.ToString("yyyy-MM-dd");

    var salesToday = (await QueryAsync(
        "SELECT COALESCE(SUM(total),0) total,COUNT(*) count FROM sales WHERE substr(created_at,1,10)=$date",
        command => Add(command, "$date", DateTime.UtcNow.ToString("yyyy-MM-dd"))))[0];

    var products = (await QueryAsync(@"
        SELECT
            COUNT(*) products,
            COALESCE(SUM(buying_price * stock_qty),0) stock_cost_value,
            COALESCE(SUM(selling_price * stock_qty),0) stock_sales_value,
            COALESCE(SUM((selling_price - buying_price) * stock_qty),0) potential_profit,
            COALESCE(SUM(CASE WHEN stock_qty <= low_stock_level THEN 1 ELSE 0 END),0) low_stock
        FROM products"))[0];

    var expenses = (await QueryAsync(
        "SELECT COALESCE(SUM(amount),0) total FROM expenses WHERE expense_date=$date",
        command => Add(command, "$date", today)))[0];

    var recent = await QueryAsync(@"
        SELECT s.invoice_no,s.total,s.payment_method,s.created_at,
               COALESCE(c.name,'Walk-in') customer
        FROM sales s
        LEFT JOIN customers c ON c.id=s.customer_id
        ORDER BY s.id DESC LIMIT 8");

    var lowStock = await QueryAsync(@"
        SELECT name,stock_qty,low_stock_level
        FROM products
        WHERE stock_qty <= low_stock_level
        ORDER BY stock_qty,name
        LIMIT 8");

    var recentRows = recent.Count == 0
        ? "<p class='muted'>No sales recorded yet.</p>"
        : $"<div class='mini-list'>{string.Join("", recent.Select(row =>
            $@"<div>
                 <span><strong>{E(row["invoice_no"])}</strong>
                 <small>{E(row["customer"])} · {E(row["payment_method"])} · {DateText(row["created_at"])}</small></span>
                 <strong>{Money(row["total"])}</strong>
               </div>"))}</div>";

    var lowRows = lowStock.Count == 0
        ? "<p class='muted'>All products are above their low-stock levels.</p>"
        : $"<div class='mini-list'>{string.Join("", lowStock.Select(row =>
            $@"<div>
                 <span><strong>{E(row["name"])}</strong><small>Threshold {row["low_stock_level"]}</small></span>
                 <strong class='stock low'>{row["stock_qty"]}</strong>
               </div>"))}</div>";

    return $@"
      <div class='head'>
        <div>
          <span class='eyebrow'>SHOP MANAGEMENT</span>
          <h1>{E(shop.Name)}</h1>
          <p>Simple daily control for lights and electrical tools.</p>
        </div>
        <a class='primary' href='/sales'>+ New Sale</a>
      </div>

      <div class='cards'>
        <div class='card'><span>Today's Sales</span><strong>{Money(salesToday["total"])}</strong><small>{salesToday["count"]} transactions</small></div>
        <div class='card'><span>Products</span><strong>{products["products"]}</strong><small>catalogue items</small></div>
        <div class='card'><span>Low Stock</span><strong>{products["low_stock"]}</strong><small>items needing attention</small></div>
        {(isOwner ? $@"<div class='card'><span>Stock Cost</span><strong>{Money(products["stock_cost_value"])}</strong><small>at buying price</small></div>
        <div class='card'><span>Stock Sales Value</span><strong>{Money(products["stock_sales_value"])}</strong><small>at selling price</small></div>
        <div class='card'><span>Potential Profit</span><strong>{Money(products["potential_profit"])}</strong><small>on current stock</small></div>
        <div class='card'><span>Today's Expenses</span><strong>{Money(expenses["total"])}</strong><small>recorded shop expenses</small></div>" : "")}
      </div>

      <div class='two'>
        <section class='card'>
        <div class='title'><h2>Quick Actions</h2></div>
        <div class='quick-grid'>
          <a class='action-card' href='/sales'><strong>New Sale</strong><span>Open the POS</span></a>
          <a class='action-card' href='/products'><strong>Products</strong><span>View and manage inventory</span></a>
          <a class='action-card' href='/customers'><strong>Add Customer</strong><span>Save customer details</span></a>
          {(isOwner ? "<a class='action-card' href='/expenses'><strong>Record Expense</strong><span>Track shop costs</span></a>" : "")}
        </div>
      </section>";
}

async Task<string> ProductsPage(bool isOwner)
{
    var products = await QueryAsync(
        "SELECT * FROM products ORDER BY category,name");

    var rows = products.Count == 0
        ? $@"<tr><td colspan='{(isOwner ? 7 : 6)}' class='muted'>No products yet.</td></tr>"
        : string.Join("", products.Select(row =>
            $@"<tr>
                <td><strong>{E(row["name"])}</strong></td>
                <td>{E(row["category"])}</td>
                <td>{E(row["sku"])}</td>
                {(isOwner ? $@"<td>{Money(row["buying_price"])}</td>" : "")}
                <td>{Money(row["selling_price"])}</td>
                <td><span class='stock {(Convert.ToInt32(row["stock_qty"]) <= Convert.ToInt32(row["low_stock_level"]) ? "low" : "")}'>{row["stock_qty"]}</span></td>
                {(isOwner ? $@"<td>
                  <form method='post' action='/products/delete' onsubmit='return confirm(""Delete this product?"")'>
                    <input type='hidden' name='id' value='{row["id"]}'>
                    <button class='link danger' type='submit'>Delete</button>
                  </form>
                </td>" : "")}
              </tr>"));

    var options = products.Count == 0
        ? "<option value=''>No products available</option>"
        : string.Join("", products.Select(row =>
            $"<option value='{row["id"]}'>{E(row["name"])} — stock {row["stock_qty"]}</option>"));

    var addProduct = isOwner
        ? @"
        <section class='card'>
          <div class='title'><h2>Add Product</h2></div>
          <form method='post' action='/products' class='form form-grid'>
            <input name='name' required placeholder='Product name'>
            <input name='sku' placeholder='SKU e.g. LGT-009'>
            <input name='category' value='Lighting' placeholder='Category'>
            <input name='buying_price' type='number' min='0' step='0.01' placeholder='Buying price'>
            <input name='selling_price' type='number' min='0' step='0.01' required placeholder='Selling price'>
            <input name='stock_qty' type='number' min='0' required placeholder='Opening stock'>
            <input name='low_stock_level' type='number' min='1' value='5' placeholder='Low stock level'>
            <button class='primary' type='submit'>Save Product</button>
          </form>
        </section>"
        : "";

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>INVENTORY</span><h1>Products</h1><p>Manage lights, bulbs, sockets, switches and electrical tools.</p></div>
      </div>

      <div class='two'>
        {addProduct}
        {(isOwner ? $@"        <section class='card'>
          <div class='title'><h2>Stock Adjustment</h2></div>
          <form method='post' action='/products/adjust' class='form'>
            <select name='product_id' required>{options}</select>
            <input name='quantity' type='number' min='1' value='1' required>
            <select name='mode'>
              <option value='in'>Stock In</option>
              <option value='out'>Stock Out</option>
            </select>
            <button class='secondary' type='submit'>Apply Adjustment</button>
          </form>
        </section>" : "")}
      </div>

      <section class='card'>
        <div class='title'><h2>Product List</h2><span>{products.Count} items</span></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Product</th><th>Category</th><th>SKU</th>{(isOwner ? "<th>Buy</th>" : "")}<th>Sell</th><th>Stock</th>{(isOwner ? "<th></th>" : "")}</tr>
            {rows}
          </table>
        </div>
      </section>";
}

async Task<string> SalesPage()
{
    var shop = await ShopSettings();

    return $@"
      <div class='head'>
        <div>
          <span class='eyebrow'>POINT OF SALE</span>
          <h1>New Sale</h1>
          <p>{E(shop.Name)} quick checkout.</p>
        </div>
        <a class='secondary' href='/reports'>Sales History</a>
      </div>

      <section class='card'>
        <div class='pos-grid'>
          <label>Customer<select id='customerSelect'></select></label>
          <label>Payment<select id='paymentMethod'>
            <option>Cash</option>
            <option>M-Pesa</option>
            <option>Card</option>
            <option>Bank</option>
          </select></label>
          <label id='paymentReferenceWrap' hidden>Transaction Reference
            <input id='paymentReference' maxlength='80' placeholder='M-Pesa reference e.g. QWE123ABC'>
          </label>
          <label>Discount<input id='discount' type='number' min='0' step='0.01' value='0'></label>
        </div>

        <div class='pos-add'>
          <select id='productSelect'></select>
          <input id='quantity' type='number' min='1' value='1'>
          <button class='primary' type='button' onclick='addToCart()'>Add Item</button>
        </div>

        <div class='tablewrap'>
          <table>
            <thead>
              <tr><th>Product</th><th>Price</th><th>Qty</th><th>Total</th><th></th></tr>
            </thead>
            <tbody id='cartBody'></tbody>
          </table>
        </div>

        <div class='pos-total'>
          <span>Subtotal <strong id='subtotal'>TSh 0</strong></span>
          <span>Discount <strong id='discountTotal'>TSh 0</strong></span>
          <span>Total <strong id='grandTotal'>TSh 0</strong></span>
        </div>

        <button class='primary widebtn' type='button' onclick='completeSale()'>Complete Sale</button>
        <p class='result' id='posMessage'></p>
      </section>

      <script src='/pos.js'></script>";
}

async Task<string> CustomersPage()
{
    var customers = await QueryAsync(
        "SELECT * FROM customers ORDER BY id DESC");

    var rows = customers.Count == 0
        ? "<tr><td colspan='4' class='muted'>No customers yet.</td></tr>"
        : string.Join("", customers.Select(row =>
            $@"<tr>
                <td><strong>{E(row["name"])}</strong></td>
                <td>{E(row["phone"])}</td>
                <td>{E(row["address"])}</td>
                <td>{DateText(row["created_at"])}</td>
              </tr>"));

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>CUSTOMERS</span><h1>Customers</h1><p>Keep contacts for repeat customers and sales records.</p></div>
      </div>

      <section class='card'>
        <div class='title'><h2>Add Customer</h2></div>
        <form method='post' action='/customers' class='form form-grid'>
          <input name='name' required placeholder='Customer name'>
          <input name='phone' placeholder='Phone number'>
          <input class='wide' name='address' placeholder='Address / area'>
          <button class='primary' type='submit'>Save Customer</button>
        </form>
      </section>

      <section class='card'>
        <div class='title'><h2>Customer List</h2><span>{customers.Count} customers</span></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Name</th><th>Phone</th><th>Address</th><th>Added</th></tr>
            {rows}
          </table>
        </div>
      </section>";
}

async Task<string> DailyClosingPage()
{
    var context = httpContextAccessor.HttpContext;
    var username = context?.User.Identity?.Name ?? "User";
    var isOwner = context?.User.IsInRole("Owner") == true;
    var today = DateTime.Today.ToString("yyyy-MM-dd");
    var error = context?.Request.Query["error"].ToString();
    var saved = context?.Request.Query["saved"].ToString() == "1";
    var closedNotice = context?.Request.Query["closed"].ToString() == "1";
    var reopenedNotice = context?.Request.Query["reopened"].ToString() == "1";
    var (startUtc, endUtc) = LocalDayUtcRange(DateTime.Today);

    var sales = (await QueryAsync(
        @"SELECT COALESCE(SUM(total),0) total,COUNT(*) count
          FROM sales WHERE created_at >= $start AND created_at < $end",
        command =>
        {
            Add(command, "$start", startUtc);
            Add(command, "$end", endUtc);
        }))[0];

    var expenses = await QueryAsync(
        @"SELECT id,category,description,amount,created_at,
                 COALESCE(recorded_by_username,'Unknown') recorded_by
          FROM expenses WHERE expense_date=$date ORDER BY id DESC",
        command => Add(command, "$date", today));

    var paymentRows = await QueryAsync(
        @"SELECT payment_method,COALESCE(SUM(total),0) total,COUNT(*) count
          FROM sales WHERE created_at >= $start AND created_at < $end
          GROUP BY payment_method ORDER BY total DESC",
        command =>
        {
            Add(command, "$start", startUtc);
            Add(command, "$end", endUtc);
        });

    var closingRows = await QueryAsync(
        @"SELECT business_date,total_sales,transaction_count,total_expenses,
                 actual_cash,actual_mpesa,actual_card,actual_bank,
                 closed_by_username,closed_at,notes
          FROM daily_closings ORDER BY business_date DESC LIMIT 30");

    var todayClosing = closingRows.FirstOrDefault(row =>
        string.Equals(row["business_date"]?.ToString(), today, StringComparison.Ordinal));

    var expectedPayments = paymentRows.ToDictionary(
        row => row["payment_method"]?.ToString() ?? "",
        row => Convert.ToDouble(row["total"] ?? 0),
        StringComparer.OrdinalIgnoreCase);

    double Expected(string method)
        => expectedPayments.TryGetValue(method, out var value) ? value : 0d;

    var totalSales = Convert.ToDouble(sales["total"] ?? 0);
    var transactionCount = Convert.ToInt32(sales["count"] ?? 0);
    var totalExpenses = expenses.Sum(row => Convert.ToDouble(row["amount"] ?? 0));
    var netAfterExpenses = totalSales - totalExpenses;
    var isClosed = todayClosing is not null;

    var notice = "";
    if (!string.IsNullOrWhiteSpace(error))
        notice += $@"<div class='notice danger'>{E(error)}</div>";
    if (saved)
        notice += "<div class='notice'>Expense recorded successfully.</div>";
    if (closedNotice)
        notice += "<div class='notice'>Today's sales have been closed successfully.</div>";
    if (reopenedNotice)
        notice += "<div class='notice'>Today's closing was reopened by the Owner.</div>";

    var paymentLines = paymentRows.Count == 0
        ? "<p class='muted'>No sales recorded today.</p>"
        : $"<div class='mini-list'>{string.Join("", paymentRows.Select(row =>
            $@"<div><span><strong>{E(row["payment_method"])}</strong><small>{row["count"]} transaction(s)</small></span><strong>{Money(row["total"])}</strong></div>"))}</div>";

    var expenseLines = expenses.Count == 0
        ? "<p class='muted'>No expenses recorded today.</p>"
        : $"<div class='mini-list'>{string.Join("", expenses.Select(row =>
            $@"<div><span><strong>{E(row["category"])}</strong><small>{E(row["description"])} · {E(row["recorded_by"])}</small></span><strong>{Money(row["amount"])}</strong></div>"))}</div>";

    var closingSection = isClosed
        ? $@"<section class='card'>
            <div class='title'><h2>Day Closed</h2><span>{E(todayClosing!["business_date"])}</span></div>
            <p>Closed by <strong>{E(todayClosing!["closed_by_username"])}</strong> at {DateText(todayClosing!["closed_at"])}.</p>
            <p class='muted'>Sales are locked for today. An Owner must reopen the day before another sale can be entered.</p>

            <div class='tablewrap'>
              <table>
                <tr><th>Payment</th><th>Expected</th><th>Actual</th><th>Difference</th></tr>
                <tr><td>Cash</td><td>{Money(Expected("Cash"))}</td><td>{Money(todayClosing!["actual_cash"])}</td><td>{Money(Convert.ToDouble(todayClosing!["actual_cash"] ?? 0) - Expected("Cash"))}</td></tr>
                <tr><td>M-Pesa</td><td>{Money(Expected("M-Pesa"))}</td><td>{Money(todayClosing!["actual_mpesa"])}</td><td>{Money(Convert.ToDouble(todayClosing!["actual_mpesa"] ?? 0) - Expected("M-Pesa"))}</td></tr>
                <tr><td>Card</td><td>{Money(Expected("Card"))}</td><td>{Money(todayClosing!["actual_card"])}</td><td>{Money(Convert.ToDouble(todayClosing!["actual_card"] ?? 0) - Expected("Card"))}</td></tr>
                <tr><td>Bank</td><td>{Money(Expected("Bank"))}</td><td>{Money(todayClosing!["actual_bank"])}</td><td>{Money(Convert.ToDouble(todayClosing!["actual_bank"] ?? 0) - Expected("Bank"))}</td></tr>
              </table>
            </div>

            {(isOwner ? $@"<form method='post' action='/daily-closing/reopen' onsubmit='return confirm(""Reopen today's sales?"")'>
              <button class='secondary' type='submit'>Reopen Today's Sales</button>
            </form>" : "")}
          </section>"
        : $@"<section class='card'>
            <div class='title'><h2>Close Today's Sales</h2><span>End of day</span></div>
            <p class='muted'>Before closing, enter the actual money counted/received for each payment method. The system will compare it with today's recorded sales.</p>
            <form method='post' action='/daily-closing/close' class='form'>
              <div class='form-grid'>
                <label>Actual Cash<input name='actual_cash' type='number' min='0' step='0.01' value='{Expected("Cash")}' required></label>
                <label>Actual M-Pesa<input name='actual_mpesa' type='number' min='0' step='0.01' value='{Expected("M-Pesa")}' required></label>
                <label>Actual Card<input name='actual_card' type='number' min='0' step='0.01' value='{Expected("Card")}' required></label>
                <label>Actual Bank<input name='actual_bank' type='number' min='0' step='0.01' value='{Expected("Bank")}' required></label>
              </div>
              <textarea name='notes' rows='3' placeholder='Closing notes (optional)'></textarea>
              <button class='primary' type='submit' onclick='return confirm(""Close today's sales now? Make sure all expenses and payment counts are correct."")'>Close Today's Sales</button>
            </form>
          </section>";

    var expenseForm = isClosed
        ? ""
        : $@"<section class='card'>
            <div class='title'><h2>Add Today's Expense</h2><span>Recorded by {E(username)}</span></div>
            <form method='post' action='/daily-closing/expense' class='form form-grid'>
              <input name='category' value='General' required placeholder='Expense category e.g. Transport'>
              <input name='amount' type='number' min='0.01' step='0.01' required placeholder='Amount'>
              <input class='wide' name='description' placeholder='What was the money spent on?'>
              <button class='primary' type='submit'>Save Expense</button>
            </form>
          </section>";

    var history = isOwner
        ? $@"<section class='card'>
            <div class='title'><h2>Closing History</h2><span>Latest {closingRows.Count}</span></div>
            <div class='tablewrap'>
              <table>
                <tr><th>Date</th><th>Sales</th><th>Transactions</th><th>Expenses</th><th>Closed By</th><th>Closed At</th></tr>
                {string.Join("", closingRows.Select(row =>
                    $@"<tr>
                      <td>{E(row["business_date"])}</td>
                      <td>{Money(row["total_sales"])}</td>
                      <td>{row["transaction_count"]}</td>
                      <td>{Money(row["total_expenses"])}</td>
                      <td>{E(row["closed_by_username"])}</td>
                      <td>{DateText(row["closed_at"])}</td>
                    </tr>"))}
              </table>
            </div>
          </section>"
        : "";

    return $@"
      <div class='head'>
        <div>
          <span class='eyebrow'>END OF DAY</span>
          <h1>Daily Closing</h1>
          <p>{DateTime.Today:dddd, dd MMMM yyyy} · employee closing and daily expense record.</p>
        </div>
      </div>

      {notice}

      <div class='cards'>
        <div class='card'><span>Today's Sales</span><strong>{Money(totalSales)}</strong><small>{transactionCount} transactions</small></div>
        <div class='card'><span>Today's Expenses</span><strong>{Money(totalExpenses)}</strong><small>recorded for today</small></div>
        <div class='card'><span>Net After Expenses</span><strong>{Money(netAfterExpenses)}</strong><small>sales minus expenses</small></div>
      </div>

      <div class='two'>
        <section class='card'>
          <div class='title'><h2>Payment Summary</h2></div>
          {paymentLines}
        </section>
        <section class='card'>
          <div class='title'><h2>Today's Expenses</h2><span>{expenses.Count} entries</span></div>
          {expenseLines}
        </section>
      </div>

      {expenseForm}
      {closingSection}
      {history}";

}
async Task<string> ExpensesPage()
{
    var expenses = await QueryAsync(
        "SELECT * FROM expenses ORDER BY id DESC LIMIT 100");

    var rows = expenses.Count == 0
        ? "<tr><td colspan='5' class='muted'>No expenses recorded yet.</td></tr>"
        : string.Join("", expenses.Select(row =>
            $@"<tr>
                <td>{DateText(row["created_at"])}</td>
                <td>{E(row["category"])}</td>
                <td>{E(row["description"])}</td>
                <td><strong>{Money(row["amount"])}</strong></td>
                <td>{E(row["recorded_by_username"])}</td>
              </tr>"));

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>EXPENSES</span><h1>Expenses</h1><p>Track transport, electricity, supplies and other shop costs.</p></div>
      </div>

      <section class='card'>
        <div class='title'><h2>Record Expense</h2></div>
        <form method='post' action='/expenses' class='form form-grid'>
          <input name='category' value='General' placeholder='Category'>
          <input name='amount' type='number' min='0.01' step='0.01' required placeholder='Amount'>
          <input class='wide' name='description' placeholder='Description e.g. delivery transport'>
          <button class='primary' type='submit'>Save Expense</button>
        </form>
      </section>

      <section class='card'>
        <div class='title'><h2>Recent Expenses</h2></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Date</th><th>Category</th><th>Description</th><th>Amount</th><th>Recorded By</th></tr>
            {rows}
          </table>
        </div>
      </section>";
}

async Task<string> ReportsPage(HttpRequest request)
{
    var isOwner = request.HttpContext.User.IsInRole("Owner");
    var period = request.Query["period"].ToString().ToLowerInvariant();

    if (period is not ("today" or "week" or "month" or "all"))
        period = "all";

    var todayLocal = DateTime.Today;
    DateTime startLocal;
    DateTime endLocal;
    string periodLabel;

    switch (period)
    {
        case "today":
            startLocal = todayLocal;
            endLocal = todayLocal.AddDays(1);
            periodLabel = "Today";
            break;

        case "week":
            var daysSinceMonday = ((int)todayLocal.DayOfWeek + 6) % 7;
            startLocal = todayLocal.AddDays(-daysSinceMonday);
            endLocal = startLocal.AddDays(7);
            periodLabel = "This Week";
            break;

        case "month":
            startLocal = new DateTime(todayLocal.Year, todayLocal.Month, 1);
            endLocal = startLocal.AddMonths(1);
            periodLabel = "This Month";
            break;

        default:
            startLocal = DateTime.MinValue;
            endLocal = DateTime.MaxValue;
            periodLabel = "All Time";
            break;
    }

    var useDateFilter = period != "all";
    var startUtc = DateTime.SpecifyKind(startLocal, DateTimeKind.Local).ToUniversalTime().ToString("O");
    var endUtc = DateTime.SpecifyKind(endLocal, DateTimeKind.Local).ToUniversalTime().ToString("O");
    var expenseStart = startLocal.ToString("yyyy-MM-dd");
    var expenseEnd = endLocal.ToString("yyyy-MM-dd");

    var salesFilter = useDateFilter
        ? " WHERE s.created_at >= $start AND s.created_at < $end"
        : "";

    var summaryRows = await QueryAsync($@"
        SELECT
            COALESCE(SUM(s.total),0) sales_total,
            COALESCE(SUM(si.cost_total),0) cost_total,
            COALESCE(SUM(s.total - si.cost_total),0) gross_profit
        FROM sales s
        LEFT JOIN (
            SELECT sale_id, COALESCE(SUM(buying_price * quantity),0) cost_total
            FROM sale_items
            GROUP BY sale_id
        ) si ON si.sale_id=s.id
        {salesFilter}",
        command =>
        {
            if (useDateFilter)
            {
                Add(command, "$start", startUtc);
                Add(command, "$end", endUtc);
            }
        });

    var summary = summaryRows[0];

    var expenseFilter = useDateFilter
        ? " WHERE expense_date >= $expenseStart AND expense_date < $expenseEnd"
        : "";

    var expenseRows = await QueryAsync(
        $"SELECT COALESCE(SUM(amount),0) total FROM expenses{expenseFilter}",
        command =>
        {
            if (useDateFilter)
            {
                Add(command, "$expenseStart", expenseStart);
                Add(command, "$expenseEnd", expenseEnd);
            }
        });

    var totalExpenses = expenseRows[0]["total"];
    var netProfit = Convert.ToDouble(summary["gross_profit"] ?? 0) - Convert.ToDouble(totalExpenses ?? 0);

    var rows = await QueryAsync($@"
        SELECT s.invoice_no,s.subtotal,s.discount,s.total,s.payment_method,s.created_at,
               COALESCE(c.name,'Walk-in Customer') customer,
               COALESCE(SUM(si.quantity),0) units,
               COALESCE(SUM(si.buying_price * si.quantity),0) cost_total,
               COALESCE(s.total - SUM(si.buying_price * si.quantity),0) gross_profit
        FROM sales s
        LEFT JOIN customers c ON c.id=s.customer_id
        LEFT JOIN sale_items si ON si.sale_id=s.id
        {salesFilter}
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT 200",
        command =>
        {
            if (useDateFilter)
            {
                Add(command, "$start", startUtc);
                Add(command, "$end", endUtc);
            }
        });

    var bodyRows = rows.Count == 0
        ? $"<tr><td colspan='{(isOwner ? 8 : 7)}' class='muted'>No sales recorded for this period.</td></tr>"
        : string.Join("", rows.Select(row =>
            $@"<tr>
                <td><a class='link' href='/receipt/{Uri.EscapeDataString(row["invoice_no"]?.ToString() ?? "")}'>{E(row["invoice_no"])}</a></td>
                <td>{DateText(row["created_at"])}</td>
                <td>{E(row["customer"])}</td>
                <td>{row["units"]}</td>
                <td>{E(row["payment_method"])}</td>
                <td>{Money(row["discount"])}</td>
                <td><strong>{Money(row["total"])}</strong></td>
                {(isOwner ? $@"<td><strong>{Money(row["gross_profit"])}</strong></td>" : "")}
              </tr>"));

    var shareText = isOwner
        ? $"SHEEHAN LIGHTS\n{periodLabel} BUSINESS REPORT\n\n" +
          $"Total Sales: {Money(summary["sales_total"])}\n" +
          $"Gross Profit: {Money(summary["gross_profit"])}\n" +
          $"Total Expenses: {Money(totalExpenses)}\n" +
          $"Net Profit: {Money(netProfit)}\n\n" +
          $"Report period: {periodLabel}\n" +
          $"Generated: {DateTime.Now:dd MMM yyyy HH:mm}"
        : $"SHEEHAN LIGHTS\n{periodLabel} SALES REPORT\n\n" +
          $"Total Sales: {Money(summary["sales_total"])}\n\n" +
          $"Report period: {periodLabel}\n" +
          $"Generated: {DateTime.Now:dd MMM yyyy HH:mm}";

    var whatsappUrl = "https://wa.me/?text=" + WebUtility.UrlEncode(shareText);

    return $@"
      <div class='head'>
        <div>
          <span class='eyebrow'>REPORTS</span>
          <h1>Sales & Profit Reports</h1>
          <p>Review sales, profit and expenses by reporting period.</p>
        </div>
        <div class='actions'>
          <button class='secondary' type='button' onclick='copyReport(this)' data-report='{E(shareText)}'>Copy Report</button>
          <a class='secondary' href='{E(whatsappUrl)}' target='_blank' rel='noopener'>Open WhatsApp</a>
          <a class='primary' href='/sales'>+ New Sale</a>
        </div>
      </div>

      <section class='card'>
        <div class='title'>
          <h2>Report Period</h2>
          <span>{E(periodLabel)}</span>
        </div>
        <div class='actions'>
          <a class='{(period == "today" ? "primary" : "secondary")}' href='/reports?period=today'>Today</a>
          <a class='{(period == "week" ? "primary" : "secondary")}' href='/reports?period=week'>This Week</a>
          <a class='{(period == "month" ? "primary" : "secondary")}' href='/reports?period=month'>This Month</a>
          <a class='{(period == "all" ? "primary" : "secondary")}' href='/reports?period=all'>All Time</a>
        </div>
      </section>

      <div class='cards'>
        <div class='card'><span>Total Sales</span><strong>{Money(summary["sales_total"])}</strong><small>{E(periodLabel)}</small></div>
        {(isOwner ? $@"<div class='card'><span>Gross Profit</span><strong>{Money(summary["gross_profit"])}</strong><small>sales minus product cost</small></div>
        <div class='card'><span>Total Expenses</span><strong>{Money(totalExpenses)}</strong><small>recorded shop expenses</small></div>
        <div class='card'><span>Net Profit</span><strong>{Money(netProfit)}</strong><small>gross profit minus expenses</small></div>" : "")}
      </div>

      <section class='card'>
        <div class='title'><h2>Sales History</h2><span>Latest 200 in selected period · view only</span></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Invoice</th><th>Date</th><th>Customer</th><th>Units</th><th>Payment</th><th>Discount</th><th>Total</th>{(isOwner ? "<th>Profit</th>" : "")}</tr>
            {bodyRows}
          </table>
        </div>
      </section>

      <p id='copyStatus' class='muted'>Tip: use <strong>Copy Report</strong> when WhatsApp cannot be reached. Paste the copied report into any WhatsApp chat.</p>
      <script>
        async function copyReport(button) {{
          const text = button.dataset.report;
          try {{
            await navigator.clipboard.writeText(text);
            const status = document.getElementById('copyStatus');
            status.textContent = 'Report copied. Open WhatsApp and paste it into the chat.';
            button.textContent = 'Copied';
            setTimeout(() => button.textContent = 'Copy Report', 2000);
          }} catch {{
            window.prompt('Copy this report and paste it into WhatsApp:', text);
          }}
        }}
      </script>";
}

async Task<string> SettingsPage()
{
    var settings = await ShopSettings();

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>BUSINESS SETUP</span><h1>Business Profile</h1><p>These settings make the document template reusable for many businesses.</p></div>
      </div>

      <form method='post' action='/settings'>
        <section class='card'>
          <div class='title'><h2>Business identity</h2><span>Branding</span></div>
          <div class='form form-grid'>
            <input name='shop_name' value='{E(settings.Name)}' required placeholder='Business name'>
            <input name='phone' value='{E(settings.Phone)}' placeholder='Phone'>
            <input name='email' value='{E(settings.Email)}' placeholder='Email'>
            <input name='currency' value='{E(settings.Currency)}' placeholder='Currency, e.g. TSh'>
            <input class='wide' name='address' value='{E(settings.Address)}' placeholder='Address'>
            <input class='wide' name='slogan' value='{E(settings.Slogan)}' placeholder='Slogan / tagline'>
            <input class='wide' name='logo_url' value='{E(settings.LogoUrl)}' placeholder='Logo image URL (optional)'>
            <input name='invoice_prefix' value='{E(settings.InvoicePrefix)}' placeholder='Proforma prefix, e.g. WL-'>
            <input name='footer_text' value='{E(settings.FooterText)}' placeholder='Document footer'>
          </div>
        </section>

        <section class='card'>
          <div class='title'><h2>Payment details</h2><span>Printed on proformas</span></div>
          <div class='form form-grid'>
            <input name='bank_name' value='{E(settings.BankName)}' placeholder='Bank name'>
            <input name='bank_account_number' value='{E(settings.BankAccountNumber)}' placeholder='Account number'>
            <input name='bank_account_name' value='{E(settings.BankAccountName)}' placeholder='Account name'>
            <input name='mobile_money_name' value='{E(settings.MobileMoneyName)}' placeholder='Mobile money label'>
            <input name='mobile_money_number' value='{E(settings.MobileMoneyNumber)}' placeholder='Mobile money number'>
          </div>
        </section>

        <button class='primary widebtn' type='submit'>Save Business Settings</button>
      </form>";
}

async Task<(string Name, string Phone, string Address, string Currency, string Email, string LogoUrl, string Slogan, string BankName, string BankAccountNumber, string BankAccountName, string MobileMoneyName, string MobileMoneyNumber, string InvoicePrefix, string FooterText)> ShopSettings()
{
    var rows = await QueryAsync(
        @"SELECT shop_name,phone,address,currency,email,logo_url,slogan,
                 bank_name,bank_account_number,bank_account_name,
                 mobile_money_name,mobile_money_number,invoice_prefix,footer_text
          FROM settings WHERE id=1");

    if (rows.Count == 0)
        return ("Business Name", "", "", "TSh", "", "", "", "", "", "", "", "", "PF-", "Thank you for your business.");

    return (
        rows[0]["shop_name"]?.ToString() ?? "Business Name",
        rows[0]["phone"]?.ToString() ?? "",
        rows[0]["address"]?.ToString() ?? "",
        rows[0]["currency"]?.ToString() ?? "TSh",
        rows[0]["email"]?.ToString() ?? "",
        rows[0]["logo_url"]?.ToString() ?? "",
        rows[0]["slogan"]?.ToString() ?? "",
        rows[0]["bank_name"]?.ToString() ?? "",
        rows[0]["bank_account_number"]?.ToString() ?? "",
        rows[0]["bank_account_name"]?.ToString() ?? "",
        rows[0]["mobile_money_name"]?.ToString() ?? "",
        rows[0]["mobile_money_number"]?.ToString() ?? "",
        rows[0]["invoice_prefix"]?.ToString() ?? "PF-",
        rows[0]["footer_text"]?.ToString() ?? "Thank you for your business.");
}


async Task<string> ProformaCreatePage()
{
    var shop = await ShopSettings();

    var rows = string.Join("", Enumerable.Range(0, 6).Select(index => $@"
      <tr>
        <td><input name='item_qty' type='number' min='1' value='{(index == 0 ? "1" : "")}' placeholder='Qty'></td>
        <td><input name='item_description' placeholder='Item / service'></td>
        <td><input name='item_price' type='number' min='0' step='0.01' placeholder='Unit price'></td>
        <td class='line-total'>{E(shop.Currency)} 0</td>
      </tr>"));

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>DOCUMENTS</span><h1>New Proforma</h1><p>Create a customer-ready document from your phone or computer.</p></div>
      </div>

      <form method='post' action='/proforma' id='proformaForm'>
        <section class='two'>
          <div class='card'>
            <div class='title'><h2>Bill to</h2><span>{E(shop.Name)}</span></div>
            <div class='form'>
              <input name='customer_name' required placeholder='Customer / company name'>
              <input name='customer_phone' placeholder='Customer phone'>
              <input name='customer_address' placeholder='Customer address'>
              <textarea name='notes' rows='4' placeholder='Notes / terms'></textarea>
            </div>
          </div>

          <div class='card'>
            <div class='title'><h2>Payment</h2><span>Configured in Settings</span></div>
            <div class='mini-list'>
              <div><span>Bank<small>{E(shop.BankName)}</small></span><strong>{E(shop.BankAccountNumber)}</strong></div>
              <div><span>Account name<small>Holder</small></span><strong>{E(shop.BankAccountName)}</strong></div>
              <div><span>{E(shop.MobileMoneyName)}<small>Mobile payment</small></span><strong>{E(shop.MobileMoneyNumber)}</strong></div>
            </div>
            <div class='form' style='margin-top:14px'>
              <input name='discount' type='number' min='0' step='0.01' value='0' placeholder='Discount'>
            </div>
          </div>
        </section>

        <section class='card'>
          <div class='title'><h2>Items</h2><span>Automatic totals</span></div>
          <div class='tablewrap'>
            <table id='proformaItems'>
              <tr><th>QTY</th><th>PARTICULARS</th><th>@</th><th>AMOUNT</th></tr>
              {rows}
            </table>
          </div>
          <div class='pos-total'>
            <span>Subtotal <strong id='subtotalText'>{E(shop.Currency)} 0</strong></span>
            <span>Discount <strong id='discountText'>{E(shop.Currency)} 0</strong></span>
            <span>Total <strong id='totalText'>{E(shop.Currency)} 0</strong></span>
          </div>
          <button class='primary widebtn' type='submit'>Create Proforma</button>
        </section>
      </form>

      <script>
        (() => {{
          const form = document.getElementById('proformaForm');
          const table = document.getElementById('proformaItems');
          const itemRows = () => Array.from(table.querySelectorAll('tr')).slice(1);
          const money = n => new Intl.NumberFormat(undefined, {{ maximumFractionDigits: 0 }}).format(Math.round(n));

          function recalc() {{
            let subtotal = 0;
            itemRows().forEach(row => {{
              const qty = Number(row.querySelector('[name='item_qty']').value || 0);
              const price = Number(row.querySelector('[name='item_price']').value || 0);
              const total = qty * price;
              subtotal += total;
              row.querySelector('.line-total').textContent = '{E(shop.Currency)} ' + money(total);
            }});

            const discount = Number(form.querySelector('[name='discount']').value || 0);
            const safeDiscount = Math.min(Math.max(discount, 0), subtotal);
            document.getElementById('subtotalText').textContent = '{E(shop.Currency)} ' + money(subtotal);
            document.getElementById('discountText').textContent = '{E(shop.Currency)} ' + money(safeDiscount);
            document.getElementById('totalText').textContent = '{E(shop.Currency)} ' + money(subtotal - safeDiscount);
          }}

          form.addEventListener('input', recalc);
          recalc();
        }})();
      </script>";
}

async Task<string> ProformaPage(int id)
{
    var rows = await QueryAsync(
        @"SELECT p.proforma_no,p.customer_name,p.customer_phone,p.customer_address,
                 p.notes,p.subtotal,p.discount,p.total,p.created_at,
                 i.description,i.quantity,i.unit_price,i.line_total
          FROM proformas p
          LEFT JOIN proforma_items i ON i.proforma_id=p.id
          WHERE p.id=$id
          ORDER BY i.id",
        command => Add(command, "$id", id));

    if (rows.Count == 0)
        return "Proforma not found.";

    var first = rows[0];
    var shop = await ShopSettings();

    string DocMoney(object? value)
        => $"{shop.Currency} " + Convert.ToDecimal(value ?? 0).ToString("N0", CultureInfo.InvariantCulture);

    var itemRows = string.Join("", rows
        .Where(row => row["description"] is not null)
        .Select(row => $@"<tr>
            <td>{E(row["quantity"])}</td>
            <td>{E(row["description"])}</td>
            <td>{DocMoney(row["unit_price"])}</td>
            <td>{DocMoney(row["line_total"])}</td>
          </tr>"));

    var paymentRows = string.Concat(
        string.IsNullOrWhiteSpace(shop.BankName) ? "" : $@"<div><strong>BANK NAME</strong><span>{E(shop.BankName)}</span></div>",
        string.IsNullOrWhiteSpace(shop.BankAccountNumber) ? "" : $@"<div><strong>ACCOUNT NUMBER</strong><span>{E(shop.BankAccountNumber)}</span></div>",
        string.IsNullOrWhiteSpace(shop.BankAccountName) ? "" : $@"<div><strong>ACCOUNT NAME</strong><span>{E(shop.BankAccountName)}</span></div>",
        string.IsNullOrWhiteSpace(shop.MobileMoneyName) && string.IsNullOrWhiteSpace(shop.MobileMoneyNumber)
            ? ""
            : $@"<div><strong>{E(shop.MobileMoneyName)}</strong><span>{E(shop.MobileMoneyNumber)}</span></div>");

    var shareText =
        $"{shop.Name}\n" +
        $"PROFORMA INVOICE {first["proforma_no"]}\n" +
        $"Customer: {first["customer_name"]}\n\n" +
        string.Join("\n", rows
            .Where(row => row["description"] is not null)
            .Select(row => $"{row["quantity"]} x {row["description"]} = {DocMoney(row["line_total"])}")) +
        $"\n\nTOTAL: {DocMoney(first["total"])}\n" +
        $"{shop.FooterText}";

    var request = httpContextAccessor.HttpContext?.Request;
    var publicUrl = request is null
        ? $"/proforma/{id}"
        : $"{request.Scheme}://{request.Host}/proforma/{id}";
    var whatsappUrl = "https://wa.me/?text=" + WebUtility.UrlEncode(shareText + "\n" + publicUrl);

    var logo = string.IsNullOrWhiteSpace(shop.LogoUrl)
        ? ""
        : $@"<img class='proforma-logo' src='{E(shop.LogoUrl)}' alt='{E(shop.Name)} logo'>";

    return $@"
      <section class='proforma-shell'>
        <div class='actions no-print'>
          <button class='primary' type='button' onclick='window.print()'>Print / Save PDF</button>
          <button class='secondary' type='button' onclick='shareProforma()'>Share</button>
          <a class='secondary' href='{E(whatsappUrl)}' target='_blank' rel='noopener'>WhatsApp</a>
          <a class='secondary' href='/proforma'>New Proforma</a>
        </div>

        <article class='proforma-paper'>
          <div class='proforma-top'>
            <div class='proforma-brand'>
              {logo}
              <h1>{E(shop.Name)}</h1>
              <p>{E(shop.Slogan)}</p>
              <p>{E(shop.Address)}</p>
              <p>{E(shop.Phone)}{(string.IsNullOrWhiteSpace(shop.Email) ? "" : $" · {E(shop.Email)}")}</p>
            </div>
            <div class='proforma-title'>
              <span>PROFORMA INVOICE</span>
              <small>{E(first["proforma_no"])}</small>
              <small>{DateText(first["created_at"])}</small>
            </div>
          </div>

          <div class='proforma-grid'>
            <section>
              <h3>BILL TO</h3>
              <strong>{E(first["customer_name"])}</strong>
              <span>{E(first["customer_phone"])}</span>
              <span>{E(first["customer_address"])}</span>
            </section>
            <section>
              <h3>PAYMENT DETAILS</h3>
              <div class='payment-grid'>{paymentRows}</div>
            </section>
          </div>

          <div class='tablewrap'>
            <table class='proforma-table'>
              <tr><th>QTY</th><th>PARTICULARS</th><th>@</th><th>AMOUNT</th></tr>
              {itemRows}
            </table>
          </div>

          <div class='proforma-total'>
            <span>SUBTOTAL <strong>{DocMoney(first["subtotal"])}</strong></span>
            <span>DISCOUNT <strong>{DocMoney(first["discount"])}</strong></span>
            <span class='grand'>TOTAL <strong>{DocMoney(first["total"])}</strong></span>
          </div>

          {(string.IsNullOrWhiteSpace(first["notes"]?.ToString()) ? "" : $@"<div class='proforma-notes'><h3>NOTES</h3><p>{E(first["notes"])}</p></div>")}

          <div class='proforma-footer'>
            <strong>{E(shop.FooterText)}</strong>
            <span>{E(shop.Name)}</span>
          </div>
        </article>
      </section>

      <script>
        async function shareProforma() {{
          const url = '{E(publicUrl)}';
          const text = {System.Text.Json.JsonSerializer.Serialize(shareText)};
          if (navigator.share) {{
            try {{
              await navigator.share({{ title: 'Proforma {E(first["proforma_no"])}', text, url }});
              return;
            }} catch {{}}
          }}
          try {{
            await navigator.clipboard.writeText(url);
            alert('Proforma link copied. Paste it into WhatsApp or another message.');
          }} catch {{
            window.prompt('Copy the proforma link:', url);
          }}
        }}
      </script>";
}

string LoginPage(string error)
{
    var message = string.IsNullOrWhiteSpace(error) ? "" : $@"<div class='notice danger'>{E(error)}</div>";

    return $@"<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>Login · Business Manager</title>
  <link rel='stylesheet' href='/style.css'>
  <link rel='manifest' href='/manifest.json'>
  <meta name='theme-color' content='#07080d'>
</head>
<body>
<main class='auth-page'>
  <section class='card auth-card'>
    <div class='brand auth-brand'>BUSINESS <span>MANAGER</span><small>POWERED BY ALBISNESSTZ</small></div>
    <span class='eyebrow'>SECURE ACCESS</span>
    <h1>Sign in</h1>
    <p>Authorized business users only.</p>
    {message}
    <form method='post' action='/login' class='form'>
      <input name='username' autocomplete='username' required placeholder='Username'>
      <input name='password' type='password' autocomplete='current-password' required placeholder='Password'>
      <button class='primary' type='submit'>Sign In</button>
    </form>
  </section>
</main>
</body>
</html>";
}

async Task<string> AccountPage(bool forceChange)
{
    var context = httpContextAccessor.HttpContext;
    var username = context?.User.Identity?.Name ?? "User";
    var error = context?.Request.Query["error"].ToString();
    var saved = context?.Request.Query["saved"].ToString() == "1";

    var notice = saved
        ? "<div class='notice'>Password updated successfully.</div>"
        : string.IsNullOrWhiteSpace(error)
            ? ""
            : $@"<div class='notice danger'>{E(error)}</div>";

    if (forceChange)
        notice += "<div class='notice'>For security, change the temporary password before using the system.</div>";

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>ACCOUNT SECURITY</span><h1>My Account</h1><p>Signed in as {E(username)}.</p></div>
      </div>
      <section class='card'>
        <h2>Change Password</h2>
        {notice}
        <form method='post' action='/account/password' class='form'>
          <input name='current_password' type='password' autocomplete='current-password' required placeholder='Current password'>
          <input name='new_password' type='password' autocomplete='new-password' minlength='12' required placeholder='New password (12+ characters)'>
          <input name='confirm_password' type='password' autocomplete='new-password' minlength='12' required placeholder='Confirm new password'>
          <button class='primary' type='submit'>Update Password</button>
        </form>
      </section>";
}

async Task<string> StaffPage(HttpRequest request)
{
    var rows = await QueryAsync(
        "SELECT id,username,role,active,must_change_password,created_at FROM users ORDER BY role,username");

    var notice = request.Query["created"] == "1"
        ? "<div class='notice'>Employee account created. Give the employee the temporary password you entered; they must change it on first login.</div>"
        : request.Query["reset"] == "1"
            ? "<div class='notice'>Employee password reset successfully. Give the new temporary password to the employee; they must change it on next login.</div>"
            : "";

    var error = request.Query["error"].ToString();
    if (!string.IsNullOrWhiteSpace(error))
        notice += $@"<div class='notice danger'>{E(error)}</div>";

    var list = rows.Count == 0
        ? "<p class='muted'>No users found.</p>"
        : $@"<div class='tablewrap'><table>
            <tr><th>Username</th><th>Role</th><th>Status</th><th>Password</th><th>Owner Actions</th></tr>
            {string.Join("", rows.Select(row =>
            $@"<tr>
                <td><strong>{E(row["username"])}</strong></td>
                <td>{E(row["role"])}</td>
                <td>{(Convert.ToInt32(row["active"]) == 1 ? "Active" : "Disabled")}</td>
                <td>{(Convert.ToInt32(row["must_change_password"]) == 1 ? "Must change" : "Set")}</td>
                <td>{(row["role"]?.ToString() == "Employee"
                    ? $@"<div class='actions'>
                        <form method='post' action='/staff/toggle'><input type='hidden' name='id' value='{row["id"]}'><button class='link' type='submit'>{(Convert.ToInt32(row["active"]) == 1 ? "Disable" : "Enable")}</button></form>
                        <form method='post' action='/staff/reset-password' class='form-inline'>
                          <input type='hidden' name='id' value='{row["id"]}'>
                          <input name='password' type='password' minlength='12' required placeholder='New temp password'>
                          <button class='link' type='submit'>Reset Password</button>
                        </form>
                      </div>"
                    : "<span class='muted'>Owner</span>")}</td>
              </tr>"))}
          </table></div>";

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>TEAM ACCESS</span><h1>Staff</h1><p>Owner controls for employee accounts.</p></div>
      </div>

      <section class='card'>
        <h2>Create Employee</h2>
        {notice}
        <form method='post' action='/staff' class='form form-grid'>
          <input name='username' required minlength='3' maxlength='32' placeholder='Employee username'>
          <input name='password' type='password' required minlength='12' placeholder='Temporary password (12+ characters)'>
          <button class='primary' type='submit'>Create Employee</button>
        </form>
      </section>

      <section class='card'>
        <div class='title'><h2>Accounts</h2><span>{rows.Count} users</span></div>
        {list}
      </section>";
}

async Task<AppUser?> FindUser(string username)
{
    if (string.IsNullOrWhiteSpace(username))
        return null;

    var rows = await QueryAsync(
        @"SELECT id,username,password_hash,role,active,must_change_password,failed_attempts,locked_until
          FROM users WHERE username=$username LIMIT 1",
        command => Add(command, "$username", username));

    return rows.Count == 0 ? null : UserFromRow(rows[0]);
}

async Task<AppUser?> FindUserById(int id)
{
    if (id <= 0)
        return null;

    var rows = await QueryAsync(
        @"SELECT id,username,password_hash,role,active,must_change_password,failed_attempts,locked_until
          FROM users WHERE id=$id LIMIT 1",
        command => Add(command, "$id", id));

    return rows.Count == 0 ? null : UserFromRow(rows[0]);
}

AppUser UserFromRow(Dictionary<string, object?> row)
{
    DateTimeOffset? locked = null;
    if (DateTimeOffset.TryParse(row["locked_until"]?.ToString(), out var parsed))
        locked = parsed;

    return new AppUser(
        Convert.ToInt32(row["id"]),
        row["username"]?.ToString() ?? "",
        row["password_hash"]?.ToString() ?? "",
        row["role"]?.ToString() ?? "Employee",
        Convert.ToInt32(row["active"]) == 1,
        Convert.ToInt32(row["must_change_password"]) == 1,
        Convert.ToInt32(row["failed_attempts"]),
        locked);
}

string HashPassword(string password)
{
    const int iterations = 600_000;
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2(
        password,
        salt,
        iterations,
        HashAlgorithmName.SHA256,
        32);

    return "PBKDF2$" + iterations.ToString(CultureInfo.InvariantCulture) + "$"
        + Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(hash);
}

bool VerifyPassword(string password, string encoded)
{
    try
    {
        var parts = encoded.Split('$');
        if (parts.Length != 4 || parts[0] != "PBKDF2")
            return false;

        if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var iterations))
            return false;

        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);

        var actual = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            HashAlgorithmName.SHA256,
            expected.Length);

        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
    catch
    {
        return false;
    }
}

string TemporaryPassword()
{
    const string chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
    var result = new char[16];

    for (var i = 0; i < result.Length; i++)
        result[i] = chars[RandomNumberGenerator.GetInt32(chars.Length)];

    return new string(result);
}

void BootstrapAdmin(SqliteConnection connection)
{
    using var count = connection.CreateCommand();
    count.CommandText = "SELECT COUNT(*) FROM users";
    if (Convert.ToInt32(count.ExecuteScalar()) > 0)
        return;

    var password = TemporaryPassword();

    using var insert = connection.CreateCommand();
    insert.CommandText = @"
        INSERT INTO users
        (username,password_hash,role,active,must_change_password,failed_attempts,created_at)
        VALUES('owner',$hash,'Owner',1,1,0,$created)";

    Add(insert, "$hash", HashPassword(password));
    Add(insert, "$created", DateTime.UtcNow.ToString("O"));
    insert.ExecuteNonQuery();

    Console.WriteLine();
    Console.WriteLine("==========================================================");
    Console.WriteLine(" SHEEHAN LIGHTS FIRST OWNER ACCOUNT");
    Console.WriteLine(" Username : owner");
    Console.WriteLine($" Temporary password : {password}");
    Console.WriteLine(" Change this password immediately after first login.");
    Console.WriteLine("==========================================================");
    Console.WriteLine();
}

async Task AuditAsync(string action, string entityType, int? entityId, string details)
{
    var context = httpContextAccessor.HttpContext;
    var userId = int.TryParse(
        context?.User.FindFirstValue(ClaimTypes.NameIdentifier),
        out var parsedUserId)
        ? (object)parsedUserId
        : DBNull.Value;

    var username = context?.User.Identity?.Name ?? "Unknown";
    var role = context?.User.FindFirstValue(ClaimTypes.Role) ?? "Unknown";
    var ip = context?.Connection.RemoteIpAddress?.ToString() ?? "";

    await ExecuteAsync(
        @"INSERT INTO audit_logs
          (user_id,username,role,action,entity_type,entity_id,details,ip_address,created_at)
          VALUES($user_id,$username,$role,$action,$entity_type,$entity_id,$details,$ip,$created)",
        command =>
        {
            Add(command, "$user_id", userId);
            Add(command, "$username", username);
            Add(command, "$role", role);
            Add(command, "$action", action);
            Add(command, "$entity_type", entityType);
            Add(command, "$entity_id", entityId.HasValue ? (object)entityId.Value : DBNull.Value);
            Add(command, "$details", details);
            Add(command, "$ip", ip);
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
        });
}

async Task<string> AuditPage()
{
    var rows = await QueryAsync(@"
        SELECT created_at,username,role,action,entity_type,entity_id,details,ip_address
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 200");

    var bodyRows = rows.Count == 0
        ? "<tr><td colspan='8' class='muted'>No audit events have been recorded yet.</td></tr>"
        : string.Join("", rows.Select(row =>
            $@"<tr>
                <td>{DateText(row["created_at"])}</td>
                <td><strong>{E(row["username"])}</strong></td>
                <td>{E(row["role"])}</td>
                <td>{E(row["action"])}</td>
                <td>{E(row["entity_type"])}{(row["entity_id"] is null ? "" : $" #{row["entity_id"]}")}</td>
                <td>{E(row["details"])}</td>
                <td>{E(row["ip_address"])}</td>
              </tr>"));

    return @"
      <div class='head'>
        <div>
          <span class='eyebrow'>SECURITY</span>
          <h1>Audit Log</h1>
          <p>Owner-only history of sensitive business actions.</p>
        </div>
      </div>

      <section class='card'>
        <div class='tablewrap'>
          <table>
            <tr><th>Date</th><th>User</th><th>Role</th><th>Action</th><th>Target</th><th>Details</th><th>IP</th></tr>
            " + bodyRows + @"
          </table>
        </div>
      </section>";
}

IResult Html(string title, string body, string active)
{
    var context = httpContextAccessor.HttpContext;
    var isOwner = context?.User.IsInRole("Owner") == true;
    var username = context?.User.Identity?.Name ?? "User";

    var ownerNav = isOwner
        ? $@"
      <a class='{(active == "expenses" ? "on" : "")}' href='/expenses'>Expenses</a>
      <a class='{(active == "staff" ? "on" : "")}' href='/staff'>Staff</a>
      <a class='{(active == "audit" ? "on" : "")}' href='/audit'>Audit Log</a>
      <a class='{(active == "settings" ? "on" : "")}' href='/settings'>Settings</a>"
        : "";

    var nav = $@"
      <a class='{(active == "home" ? "on" : "")}' href='/'>Dashboard</a>
      <a class='{(active == "sales" ? "on" : "")}' href='/sales'>New Sale</a>
      <a class='{(active == "proforma" ? "on" : "")}' href='/proforma'>Proforma</a>
      <a class='{(active == "products" ? "on" : "")}' href='/products'>Products</a>
      <a class='{(active == "customers" ? "on" : "")}' href='/customers'>Customers</a>
      <a class='{(active == "reports" ? "on" : "")}' href='/reports'>Reports</a>
      <a class='{(active == "daily" ? "on" : "")}' href='/daily-closing'>Daily Closing</a>
      {ownerNav}
      <a class='{(active == "account" ? "on" : "")}' href='/account'>Account</a>
      <a href='/logout'>Logout</a>";

    return Results.Content($@"<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>{E(title)} · Business Manager</title>
  <link rel='stylesheet' href='/style.css'>
</head>
<body>
<header class='topbar'>
  <div>
    <div class='brand'>BUSINESS <span>MANAGER</span><small>POWERED BY ALBISNESSTZ</small></div>
    <div class='muted userbar'>Signed in as {E(username)} · {E(isOwner ? "Owner" : "Employee")}</div>
  </div>
  <nav>{nav}</nav>
</header>
<main>{body}</main>
<footer>Business Manager · HybridBusinessPOS · Secure local database · AlbisnessTz</footer>
<script>
  if ('serviceWorker' in navigator) {{
    window.addEventListener('load', () => navigator.serviceWorker.register('/service-worker.js'));
  }}
</script>
</body>
</html>","text/html");
}


async Task ExecuteAsync(string sql, Action<SqliteCommand> bind)
{
    await using var connection = new SqliteConnection(ConnectionString());
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = sql;
    bind(command);
    await command.ExecuteNonQueryAsync();
}

async Task<List<Dictionary<string, object?>>> QueryAsync(
    string sql,
    Action<SqliteCommand>? bind = null)
{
    await using var connection = new SqliteConnection(ConnectionString());
    await connection.OpenAsync();
    await using var command = connection.CreateCommand();
    command.CommandText = sql;
    bind?.Invoke(command);

    await using var reader = await command.ExecuteReaderAsync();
    var rows = new List<Dictionary<string, object?>>();

    while (await reader.ReadAsync())
    {
        var row = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < reader.FieldCount; i++)
            row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);

        rows.Add(row);
    }

    return rows;
}

void Add(SqliteCommand command, string name, object? value)
    => command.Parameters.AddWithValue(name, value ?? DBNull.Value);

int ParseInt(string value, int fallback = 0)
    => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var number)
        ? number
        : fallback;

int ParseFormInt(Microsoft.Extensions.Primitives.StringValues value, int fallback = 0)
    => ParseInt(value.ToString(), fallback);

double ParseMoney(string value)
    => double.TryParse(value, NumberStyles.Number, CultureInfo.InvariantCulture, out var number)
        ? number
        : 0d;

double ParseFormMoney(Microsoft.Extensions.Primitives.StringValues value)
    => ParseMoney(value.ToString());

string E(object? value)
    => WebUtility.HtmlEncode(value?.ToString() ?? "");

string Money(object? value)
    => "TSh " + Convert.ToDecimal(value ?? 0).ToString("N0", CultureInfo.InvariantCulture);

string DateText(object? value)
    => DateTimeOffset.TryParse(value?.ToString(), out var date)
        ? date.ToLocalTime().ToString("dd MMM yyyy HH:mm")
        : value?.ToString() ?? "";

string NormalizePhone(string? value)
{
    var phone = new string((value ?? "").Where(char.IsDigit).ToArray());

    if (phone.StartsWith("00"))
        phone = phone[2..];

    if (phone.StartsWith("0"))
        phone = "255" + phone[1..];

    return phone;
}

bool IsSameOriginRequest(HttpContext context)
{
    var origin = context.Request.Headers.Origin.ToString();

    if (!string.IsNullOrWhiteSpace(origin))
        return IsSameAuthority(origin, context.Request.Host.Value);

    var referer = context.Request.Headers.Referer.ToString();

    if (!string.IsNullOrWhiteSpace(referer))
        return IsSameAuthority(referer, context.Request.Host.Value);

    return false;
}

(string StartUtc, string EndUtc) LocalDayUtcRange(DateTime localDate)
{
    var start = DateTime.SpecifyKind(localDate.Date, DateTimeKind.Local);
    var end = start.AddDays(1);

    return (
        start.ToUniversalTime().ToString("O"),
        end.ToUniversalTime().ToString("O"));
}

bool IsSameAuthority(string value, string? expectedHost)
{
    if (string.IsNullOrWhiteSpace(expectedHost))
        return false;

    if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        return false;

    return string.Equals(uri.Authority, expectedHost, StringComparison.OrdinalIgnoreCase);
}

bool AllowLoginAttempt(string clientKey)
{
    var now = DateTimeOffset.UtcNow;
    var state = loginThrottle.GetOrAdd(
        clientKey,
        _ => new LoginAttemptState(now, 0));

    lock (state)
    {
        if (now - state.WindowStart >= TimeSpan.FromMinutes(10))
        {
            state.WindowStart = now;
            state.Count = 0;
        }

        return state.Count < 10;
    }
}

void RegisterFailedLoginAttempt(string clientKey)
{
    var state = loginThrottle.GetOrAdd(
        clientKey,
        _ => new LoginAttemptState(DateTimeOffset.UtcNow, 0));

    lock (state)
    {
        state.Count++;
    }
}

void ClearLoginAttempts(string clientKey)
{
    loginThrottle.TryRemove(clientKey, out _);
}

void CreateAutomaticBackup()
{
    try
    {
        if (!File.Exists(dbPath))
            return;

        var backupDirectory = Path.Combine(app.Environment.ContentRootPath, "backups");
        Directory.CreateDirectory(backupDirectory);

        var backupPath = Path.Combine(
            backupDirectory,
            $"sheehan_lights_{DateTime.Now:yyyyMMdd_HHmmss_fff}.db");

        using var connection = new SqliteConnection(ConnectionString());
        connection.Open();

        using var command = connection.CreateCommand();
        var safeBackupPath = backupPath.Replace("'", "''");
        command.CommandText = $"VACUUM INTO '{safeBackupPath}'";
        command.ExecuteNonQuery();

        var backups = new DirectoryInfo(backupDirectory)
            .GetFiles("sheehan_lights_*.db")
            .OrderByDescending(file => file.CreationTimeUtc)
            .ToList();

        foreach (var oldBackup in backups.Skip(14))
        {
            try { oldBackup.Delete(); } catch { }
        }
    }
    catch
    {
    }
}

void InitializeDatabase()
{
    using var connection = new SqliteConnection(ConnectionString());
    connection.Open();

    if (TableExists(connection, "sales") && !ColumnExists(connection, "sales", "subtotal"))
    {
        var legacyName = "sales_legacy_" + DateTime.Now.ToString("yyyyMMddHHmmss");
        using var rename = connection.CreateCommand();
        rename.CommandText = $"ALTER TABLE sales RENAME TO {legacyName}";
        rename.ExecuteNonQuery();
    }

    using var command = connection.CreateCommand();
    command.CommandText = @"
CREATE TABLE IF NOT EXISTS audit_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NULL,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id INTEGER NULL,
    details TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Owner','Employee')),
    active INTEGER NOT NULL DEFAULT 1,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings(
    id INTEGER PRIMARY KEY CHECK(id=1),
    shop_name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    currency TEXT NOT NULL DEFAULT 'TSh',
    email TEXT,
    logo_url TEXT,
    slogan TEXT,
    bank_name TEXT,
    bank_account_number TEXT,
    bank_account_name TEXT,
    mobile_money_name TEXT,
    mobile_money_number TEXT,
    invoice_prefix TEXT NOT NULL DEFAULT 'PF-',
    footer_text TEXT NOT NULL DEFAULT 'Thank you for your business.'
);

CREATE TABLE IF NOT EXISTS proformas(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proforma_no TEXT NOT NULL UNIQUE,
    customer_name TEXT NOT NULL,
    customer_phone TEXT,
    customer_address TEXT,
    notes TEXT,
    subtotal REAL NOT NULL,
    discount REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proforma_items(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proforma_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    line_total REAL NOT NULL,
    FOREIGN KEY(proforma_id) REFERENCES proformas(id)
);

CREATE TABLE IF NOT EXISTS products(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    sku TEXT,
    category TEXT NOT NULL DEFAULT 'General',
    buying_price REAL NOT NULL DEFAULT 0,
    selling_price REAL NOT NULL DEFAULT 0,
    stock_qty INTEGER NOT NULL DEFAULT 0,
    low_stock_level INTEGER NOT NULL DEFAULT 5,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS customers(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT,
    address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sales(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_no TEXT NOT NULL UNIQUE,
    customer_id INTEGER NULL,
    subtotal REAL NOT NULL,
    discount REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL,
    payment_method TEXT NOT NULL,
    payment_reference TEXT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sale_items(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sale_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    unit_price REAL NOT NULL,
    buying_price REAL NOT NULL,
    line_total REAL NOT NULL,
    FOREIGN KEY(sale_id) REFERENCES sales(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS expenses(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    description TEXT,
    amount REAL NOT NULL,
    expense_date TEXT NOT NULL,
    created_at TEXT NOT NULL,
    recorded_by_user_id INTEGER NULL,
    recorded_by_username TEXT NULL
);

CREATE TABLE IF NOT EXISTS daily_closings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    business_date TEXT NOT NULL UNIQUE,
    closed_by_user_id INTEGER NULL,
    closed_by_username TEXT NOT NULL,
    total_sales REAL NOT NULL DEFAULT 0,
    transaction_count INTEGER NOT NULL DEFAULT 0,
    total_expenses REAL NOT NULL DEFAULT 0,
    actual_cash REAL NULL,
    actual_mpesa REAL NULL,
    actual_card REAL NULL,
    actual_bank REAL NULL,
    notes TEXT,
    closed_at TEXT NOT NULL
);

INSERT OR IGNORE INTO settings
(id,shop_name,phone,address,currency,email,logo_url,slogan,bank_name,bank_account_number,bank_account_name,mobile_money_name,mobile_money_number,invoice_prefix,footer_text)
VALUES
(1,'Sheehan Lights','','','TSh','','','Deals with decorations and light design',
 'CRDB','','','Tigo Lipa','','WL-','With our company, you are in good hands · Welcome');";
    command.ExecuteNonQuery();

    EnsureColumn(connection, "settings", "email", "TEXT");
    EnsureColumn(connection, "settings", "logo_url", "TEXT");
    EnsureColumn(connection, "settings", "slogan", "TEXT");
    EnsureColumn(connection, "settings", "bank_name", "TEXT");
    EnsureColumn(connection, "settings", "bank_account_number", "TEXT");
    EnsureColumn(connection, "settings", "bank_account_name", "TEXT");
    EnsureColumn(connection, "settings", "mobile_money_name", "TEXT");
    EnsureColumn(connection, "settings", "mobile_money_number", "TEXT");
    EnsureColumn(connection, "settings", "invoice_prefix", "TEXT NOT NULL DEFAULT 'PF-'");
    EnsureColumn(connection, "settings", "footer_text", "TEXT NOT NULL DEFAULT 'Thank you for your business.'");

    using (var settingsDefaults = connection.CreateCommand())
    {
        settingsDefaults.CommandText = @"
            UPDATE settings
            SET shop_name=CASE WHEN TRIM(COALESCE(shop_name,''))='' THEN 'Sheehan Lights' ELSE shop_name END,
                currency=CASE WHEN TRIM(COALESCE(currency,''))='' THEN 'TSh' ELSE currency END,
                invoice_prefix=CASE WHEN TRIM(COALESCE(invoice_prefix,''))='' THEN 'WL-' ELSE invoice_prefix END,
                footer_text=CASE WHEN TRIM(COALESCE(footer_text,''))='' THEN 'With our company, you are in good hands · Welcome' ELSE footer_text END
            WHERE id=1";
        settingsDefaults.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "sales", "payment_reference"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE sales ADD COLUMN payment_reference TEXT NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "daily_closings", "actual_cash"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE daily_closings ADD COLUMN actual_cash REAL NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "daily_closings", "actual_mpesa"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE daily_closings ADD COLUMN actual_mpesa REAL NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "daily_closings", "actual_card"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE daily_closings ADD COLUMN actual_card REAL NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "daily_closings", "actual_bank"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE daily_closings ADD COLUMN actual_bank REAL NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "expenses", "recorded_by_user_id"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE expenses ADD COLUMN recorded_by_user_id INTEGER NULL";
        alter.ExecuteNonQuery();
    }

    if (!ColumnExists(connection, "expenses", "recorded_by_username"))
    {
        using var alter = connection.CreateCommand();
        alter.CommandText = "ALTER TABLE expenses ADD COLUMN recorded_by_username TEXT NULL";
        alter.ExecuteNonQuery();
    }

    BootstrapAdmin(connection);

    var legacyTables = GetLegacySalesTables(connection);

    foreach (var legacy in legacyTables)
    {
        using var migrateSale = connection.CreateCommand();
        migrateSale.CommandText = $@"
            INSERT OR IGNORE INTO sales(invoice_no,customer_id,subtotal,discount,total,payment_method,created_at)
            SELECT invoice_no,NULL,total+discount,discount,total,payment_method,created_at
            FROM {legacy}";

        migrateSale.ExecuteNonQuery();

        using var migrateItems = connection.CreateCommand();
        migrateItems.CommandText = $@"
            INSERT INTO sale_items(sale_id,product_id,quantity,unit_price,buying_price,line_total)
            SELECT s.id,l.product_id,l.quantity,l.unit_price,
                   COALESCE(p.buying_price,0),l.total
            FROM {legacy} l
            JOIN sales s ON s.invoice_no=l.invoice_no
            LEFT JOIN products p ON p.id=l.product_id
            WHERE NOT EXISTS(
                SELECT 1 FROM sale_items si
                WHERE si.sale_id=s.id AND si.product_id=l.product_id
            )";

        migrateItems.ExecuteNonQuery();
    }

    using var countCommand = connection.CreateCommand();
    countCommand.CommandText = "SELECT COUNT(*) FROM products";

    if (Convert.ToInt32(countCommand.ExecuteScalar()) == 0)
    {
        var seed = new[]
        {
            ("LED Bulb 12W","LGT-001","LED Bulbs",2500d,4000d,30,5),
            ("LED Bulb 18W","LGT-002","LED Bulbs",4000d,6000d,25,5),
            ("LED Strip 5M","LGT-003","LED Strips",9000d,15000d,15,3),
            ("Ceiling Light 24W","LGT-004","Ceiling Lights",18000d,28000d,10,2),
            ("Flood Light 50W","LGT-005","Outdoor Lights",25000d,38000d,8,2),
            ("2-Way Switch","ELC-001","Electrical Tools",1500d,2500d,50,10),
            ("13A Socket","ELC-002","Electrical Tools",3000d,5000d,40,10),
            ("Electrical Tape","ELC-003","Electrical Tools",800d,1500d,60,15)
        };

        foreach (var product in seed)
        {
            using var insert = connection.CreateCommand();
            insert.CommandText = @"
                INSERT INTO products
                (name,sku,category,buying_price,selling_price,stock_qty,low_stock_level,created_at)
                VALUES($name,$sku,$category,$buying,$selling,$stock,$low,$created)";

            Add(insert, "$name", product.Item1);
            Add(insert, "$sku", product.Item2);
            Add(insert, "$category", product.Item3);
            Add(insert, "$buying", product.Item4);
            Add(insert, "$selling", product.Item5);
            Add(insert, "$stock", product.Item6);
            Add(insert, "$low", product.Item7);
            Add(insert, "$created", DateTime.UtcNow.ToString("O"));

            insert.ExecuteNonQuery();
        }
    }
}

bool TableExists(SqliteConnection connection, string table)
{
    using var command = connection.CreateCommand();
    command.CommandText =
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=$name";
    Add(command, "$name", table);
    return Convert.ToInt32(command.ExecuteScalar()) > 0;
}

bool ColumnExists(SqliteConnection connection, string table, string column)
{
    using var command = connection.CreateCommand();
    command.CommandText = $"PRAGMA table_info({table})";

    using var reader = command.ExecuteReader();

    while (reader.Read())
    {
        if (string.Equals(reader["name"]?.ToString(), column, StringComparison.OrdinalIgnoreCase))
            return true;
    }

    return false;
}

void EnsureColumn(SqliteConnection connection, string table, string column, string definition)
{
    if (ColumnExists(connection, table, column))
        return;

    using var alter = connection.CreateCommand();
    alter.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {definition}";
    alter.ExecuteNonQuery();
}

List<string> GetLegacySalesTables(SqliteConnection connection)
{
    using var command = connection.CreateCommand();
    command.CommandText =
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'sales_legacy_%'";

    using var reader = command.ExecuteReader();
    var tables = new List<string>();

    while (reader.Read())
    {
        var name = reader["name"]?.ToString();

        if (!string.IsNullOrWhiteSpace(name))
            tables.Add(name);
    }

    return tables;
}

record AppUser(
    int Id,
    string Username,
    string PasswordHash,
    string Role,
    bool Active,
    bool MustChangePassword,
    int FailedAttempts,
    DateTimeOffset? LockedUntil);

record CheckoutRequest(
    int? CustomerId,
    string? PaymentMethod,
    string? PaymentReference,
    double Discount,
    List<CheckoutItem> Items);

record CheckoutItem(int ProductId, int Quantity);

record CheckoutLine(
    int ProductId,
    string ProductName,
    int Quantity,
    double BuyingPrice,
    double SellingPrice,
    double LineTotal);


sealed class LoginAttemptState
{
    public DateTimeOffset WindowStart { get; set; }
    public int Count { get; set; }

    public LoginAttemptState(DateTimeOffset windowStart, int count)
    {
        WindowStart = windowStart;
        Count = count;
    }
}
