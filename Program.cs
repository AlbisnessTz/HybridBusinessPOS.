using Microsoft.Data.Sqlite;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/forbidden";
        options.Cookie.Name = "SheehanLights.Auth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorization();
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("login", limiter =>
    {
        limiter.PermitLimit = 5;
        limiter.Window = TimeSpan.FromMinutes(1);
        limiter.QueueLimit = 0;
    });
});

var app = builder.Build();
var httpContextAccessor = app.Services.GetRequiredService<IHttpContextAccessor>();

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

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

    if (context.User.FindFirstValue("must_change_password") == "1" &&
        !path.StartsWithSegments("/account") &&
        !path.StartsWithSegments("/logout"))
    {
        context.Response.Redirect("/account?change=1");
        return;
    }

    await next();
});

var dbPath = Path.Combine(app.Environment.ContentRootPath, "sheehan_lights.db");
InitializeDatabase();
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
    var form = await request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();

    var user = await FindUser(username);

    if (user is null)
        return Results.Redirect("/login?error=Invalid%20username%20or%20password");

    if (user.LockedUntil.HasValue && user.LockedUntil.Value > DateTimeOffset.UtcNow)
        return Results.Redirect("/login?error=Account%20temporarily%20locked%20after%20too%20many%20failed%20attempts");

    if (!user.Active)
        return Results.Redirect("/login?error=This%20account%20is%20disabled");

    if (!VerifyPassword(password, user.PasswordHash))
    {
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

    var returnUrl = form["returnUrl"].ToString();
    return string.IsNullOrWhiteSpace(returnUrl) || !returnUrl.StartsWith("/")
        ? Results.Redirect("/")
        : Results.Redirect(returnUrl);
}).RequireRateLimiting("login");

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

    return Results.Redirect("/products?saved=1");
});

app.MapPost("/products/adjust", async (HttpRequest request) =>
{
    var form = await request.ReadFormAsync();
    var productId = ParseFormInt(form["product_id"]);
    var quantity = ParseFormInt(form["quantity"]);
    var mode = form["mode"].ToString();

    if (productId <= 0 || quantity <= 0)
        return Results.BadRequest("Invalid stock adjustment.");

    var delta = mode == "out" ? -quantity : quantity;

    await ExecuteAsync(
        "UPDATE products SET stock_qty = MAX(0, stock_qty + $delta) WHERE id = $id",
        command =>
        {
            Add(command, "$delta", delta);
            Add(command, "$id", productId);
        });

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

    var form = await request.ReadFormAsync();
    var category = string.IsNullOrWhiteSpace(form["category"])
        ? "General"
        : form["category"].ToString().Trim();
    var description = form["description"].ToString().Trim();
    var amount = ParseFormMoney(form["amount"]);

    if (amount <= 0)
        return Results.BadRequest("Expense amount must be greater than zero.");

    await ExecuteAsync(
        "INSERT INTO expenses(category,description,amount,expense_date,created_at) VALUES($category,$description,$amount,$date,$created)",
        command =>
        {
            Add(command, "$category", category);
            Add(command, "$description", description);
            Add(command, "$amount", amount);
            Add(command, "$date", DateTime.Now.ToString("yyyy-MM-dd"));
            Add(command, "$created", DateTime.UtcNow.ToString("O"));
        });

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
            (invoice_no,customer_id,subtotal,discount,total,payment_method,created_at)
            VALUES($invoice,$customer,$subtotal,$discount,$total,$payment,$created)
            RETURNING id";

        Add(saleCommand, "$invoice", invoice);
        Add(saleCommand, "$customer",
            input.CustomerId.HasValue ? (object)input.CustomerId.Value : DBNull.Value);
        Add(saleCommand, "$subtotal", subtotal);
        Add(saleCommand, "$discount", discount);
        Add(saleCommand, "$total", total);
        Add(saleCommand, "$payment",
            string.IsNullOrWhiteSpace(input.PaymentMethod)
                ? "Cash"
                : input.PaymentMethod);
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

        await transaction.CommitAsync();

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
        @"SELECT s.invoice_no,s.subtotal,s.discount,s.total,s.payment_method,s.created_at,
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

    return Results.Redirect("/staff");
});

app.MapGet("/reports", async (HttpRequest request) =>
{
    if (!request.HttpContext.User.IsInRole("Owner"))
        return Results.Forbid();

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

    await ExecuteAsync(
        @"UPDATE settings
          SET shop_name=$name,phone=$phone,address=$address,currency=$currency
          WHERE id=1",
        command =>
        {
            Add(command, "$name", form["shop_name"].ToString().Trim());
            Add(command, "$phone", form["phone"].ToString().Trim());
            Add(command, "$address", form["address"].ToString().Trim());
            Add(command, "$currency",
                string.IsNullOrWhiteSpace(form["currency"])
                    ? "TSh"
                    : form["currency"].ToString().Trim());
        });

    return Results.Redirect("/settings?saved=1");
});

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
        {(isOwner ? $@"<div class='card'><span>Stock Cost</span><strong>{Money(products["stock_cost_value"])}</strong><small>at buying price</small></div>
        <div class='card'><span>Stock Sales Value</span><strong>{Money(products["stock_sales_value"])}</strong><small>at selling price</small></div>
        <div class='card'><span>Potential Profit</span><strong>{Money(products["potential_profit"])}</strong><small>on current stock</small></div>
        <div class='card'><span>Today's Expenses</span><strong>{Money(expenses["total"])}</strong><small>recorded shop expenses</small></div>" : $@"<div class='card'><span>Low Stock</span><strong>{products["low_stock"]}</strong><small>items needing attention</small></div>")}
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
        ? "<tr><td colspan='7' class='muted'>No products yet.</td></tr>"
        : string.Join("", products.Select(row =>
            $@"<tr>
                <td><strong>{E(row["name"])}</strong></td>
                <td>{E(row["category"])}</td>
                <td>{E(row["sku"])}</td>
                <td>{Money(row["buying_price"])}</td>
                <td>{Money(row["selling_price"])}</td>
                <td><span class='stock {(Convert.ToInt32(row["stock_qty"]) <= Convert.ToInt32(row["low_stock_level"]) ? "low" : "")}'>{row["stock_qty"]}</span></td>
                <td>
                  <form method='post' action='/products/delete' onsubmit='return confirm(""Delete this product?"")'>
                    <input type='hidden' name='id' value='{row["id"]}'>
                    <button class='link danger' type='submit'>Delete</button>
                  </form>
                </td>
              </tr>"));

    var options = products.Count == 0
        ? "<option value=''>No products available</option>"
        : string.Join("", products.Select(row =>
            $"<option value='{row["id"]}'>{E(row["name"])} — stock {row["stock_qty"]}</option>"));

    return $@"
      <div class='head'>
        <div><span class='eyebrow'>INVENTORY</span><h1>Products</h1><p>Manage lights, bulbs, sockets, switches and electrical tools.</p></div>
      </div>

      <div class='two'>
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
        </section>

        <section class='card'>
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
        </section>
      </div>

      <section class='card'>
        <div class='title'><h2>Product List</h2><span>{products.Count} items</span></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Product</th><th>Category</th><th>SKU</th><th>Buy</th><th>Sell</th><th>Stock</th><th></th></tr>
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

async Task<string> ExpensesPage()
{
    var expenses = await QueryAsync(
        "SELECT * FROM expenses ORDER BY id DESC LIMIT 100");

    var rows = expenses.Count == 0
        ? "<tr><td colspan='4' class='muted'>No expenses recorded yet.</td></tr>"
        : string.Join("", expenses.Select(row =>
            $@"<tr>
                <td>{DateText(row["created_at"])}</td>
                <td>{E(row["category"])}</td>
                <td>{E(row["description"])}</td>
                <td><strong>{Money(row["amount"])}</strong></td>
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
            <tr><th>Date</th><th>Category</th><th>Description</th><th>Amount</th></tr>
            {rows}
          </table>
        </div>
      </section>";
}

async Task<string> ReportsPage(HttpRequest request)
{
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
        ? "<tr><td colspan='8' class='muted'>No sales recorded for this period.</td></tr>"
        : string.Join("", rows.Select(row =>
            $@"<tr>
                <td><a class='link' href='/receipt/{Uri.EscapeDataString(row["invoice_no"]?.ToString() ?? "")}'>{E(row["invoice_no"])}</a></td>
                <td>{DateText(row["created_at"])}</td>
                <td>{E(row["customer"])}</td>
                <td>{row["units"]}</td>
                <td>{E(row["payment_method"])}</td>
                <td>{Money(row["discount"])}</td>
                <td><strong>{Money(row["total"])}</strong></td>
                <td><strong>{Money(row["gross_profit"])}</strong></td>
              </tr>"));

    var shareText =
        $"SHEEHAN LIGHTS\n{periodLabel} BUSINESS REPORT\n\n" +
        $"Total Sales: {Money(summary["sales_total"])}\n" +
        $"Gross Profit: {Money(summary["gross_profit"])}\n" +
        $"Total Expenses: {Money(totalExpenses)}\n" +
        $"Net Profit: {Money(netProfit)}\n\n" +
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
        <div class='card'><span>Gross Profit</span><strong>{Money(summary["gross_profit"])}</strong><small>sales minus product cost</small></div>
        <div class='card'><span>Total Expenses</span><strong>{Money(totalExpenses)}</strong><small>recorded shop expenses</small></div>
        <div class='card'><span>Net Profit</span><strong>{Money(netProfit)}</strong><small>gross profit minus expenses</small></div>
      </div>

      <section class='card'>
        <div class='title'><h2>Sales History</h2><span>Latest 200 in selected period</span></div>
        <div class='tablewrap'>
          <table>
            <tr><th>Invoice</th><th>Date</th><th>Customer</th><th>Units</th><th>Payment</th><th>Discount</th><th>Total</th><th>Profit</th></tr>
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
        <div><span class='eyebrow'>BUSINESS SETUP</span><h1>Settings</h1><p>Configure the details shown on the dashboard and receipts.</p></div>
      </div>

      <section class='card'>
        <form method='post' action='/settings' class='form form-grid'>
          <input name='shop_name' value='{E(settings.Name)}' required placeholder='Shop name'>
          <input name='phone' value='{E(settings.Phone)}' placeholder='Phone'>
          <input class='wide' name='address' value='{E(settings.Address)}' placeholder='Address'>
          <input name='currency' value='{E(settings.Currency)}' placeholder='Currency'>
          <button class='primary' type='submit'>Save Settings</button>
        </form>
      </section>";
}

async Task<(string Name, string Phone, string Address, string Currency)> ShopSettings()
{
    var rows = await QueryAsync(
        "SELECT shop_name,phone,address,currency FROM settings WHERE id=1");

    if (rows.Count == 0)
        return ("Sheehan Lights", "", "", "TSh");

    return (
        rows[0]["shop_name"]?.ToString() ?? "Sheehan Lights",
        rows[0]["phone"]?.ToString() ?? "",
        rows[0]["address"]?.ToString() ?? "",
        rows[0]["currency"]?.ToString() ?? "TSh");
}

string LoginPage(string error)
{
    var message = string.IsNullOrWhiteSpace(error) ? "" : $@"<div class='notice danger'>{E(error)}</div>";

    return $@"<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>Login · Sheehan Lights</title>
  <link rel='stylesheet' href='/style.css'>
</head>
<body>
<main class='auth-page'>
  <section class='card auth-card'>
    <div class='brand auth-brand'>SHEEHAN <span>LIGHTS</span><small>BUSINESS MANAGER</small></div>
    <span class='eyebrow'>SECURE ACCESS</span>
    <h1>Sign in</h1>
    <p>Authorized Sheehan Lights users only.</p>
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
    var saved = context?.Request.Query["saved"] == "1";

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
        : "";

    var error = request.Query["error"].ToString();
    if (!string.IsNullOrWhiteSpace(error))
        notice += $@"<div class='notice danger'>{E(error)}</div>";

    var list = rows.Count == 0
        ? "<p class='muted'>No users found.</p>"
        : $@"<div class='tablewrap'><table>
            <tr><th>Username</th><th>Role</th><th>Status</th><th>Password</th><th>Action</th></tr>
            {string.Join("", rows.Select(row =>
            $@"<tr>
                <td><strong>{E(row["username"])}</strong></td>
                <td>{E(row["role"])}</td>
                <td>{(Convert.ToInt32(row["active"]) == 1 ? "Active" : "Disabled")}</td>
                <td>{(Convert.ToInt32(row["must_change_password"]) == 1 ? "Must change" : "Set")}</td>
                <td>{(row["role"]?.ToString() == "Employee"
                    ? $@"<form method='post' action='/staff/toggle'><input type='hidden' name='id' value='{row["id"]}'><button class='link' type='submit'>{(Convert.ToInt32(row["active"]) == 1 ? "Disable" : "Enable")}</button></form>"
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

record AppUser(
    int Id,
    string Username,
    string PasswordHash,
    string Role,
    bool Active,
    bool MustChangePassword,
    int FailedAttempts,
    DateTimeOffset? LockedUntil);

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

IResult Html(string title, string body, string active)
{
    var context = httpContextAccessor.HttpContext;
    var isOwner = context?.User.IsInRole("Owner") == true;
    var username = context?.User.Identity?.Name ?? "User";

    var ownerNav = isOwner
        ? $@"
      <a class='{(active == "expenses" ? "on" : "")}' href='/expenses'>Expenses</a>
      <a class='{(active == "reports" ? "on" : "")}' href='/reports'>Reports</a>
      <a class='{(active == "staff" ? "on" : "")}' href='/staff'>Staff</a>
      <a class='{(active == "settings" ? "on" : "")}' href='/settings'>Settings</a>"
        : "";

    var nav = $@"
      <a class='{(active == "home" ? "on" : "")}' href='/'>Dashboard</a>
      <a class='{(active == "sales" ? "on" : "")}' href='/sales'>New Sale</a>
      <a class='{(active == "products" ? "on" : "")}' href='/products'>Products</a>
      <a class='{(active == "customers" ? "on" : "")}' href='/customers'>Customers</a>
      {ownerNav}
      <a class='{(active == "account" ? "on" : "")}' href='/account'>Account</a>
      <a href='/logout'>Logout</a>";

    return Results.Content($@"<!doctype html>
<html lang='en'>
<head>
  <meta charset='utf-8'>
  <meta name='viewport' content='width=device-width,initial-scale=1'>
  <title>{E(title)} · Sheehan Lights</title>
  <link rel='stylesheet' href='/style.css'>
</head>
<body>
<header class='topbar'>
  <div>
    <div class='brand'>SHEEHAN <span>LIGHTS</span><small>BUSINESS MANAGER</small></div>
    <div class='muted userbar'>Signed in as {E(username)} · {E(isOwner ? "Owner" : "Employee")}</div>
  </div>
  <nav>{nav}</nav>
</header>
<main>{body}</main>
<footer>Sheehan Lights · HybridBusinessPOS · Secure local database</footer>
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
    currency TEXT NOT NULL DEFAULT 'TSh'
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
    created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO settings(id,shop_name,phone,address,currency)
VALUES(1,'Sheehan Lights','','','TSh');";
    command.ExecuteNonQuery();

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

record CheckoutRequest(
    int? CustomerId,
    string? PaymentMethod,
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
