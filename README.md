# HybridBusinessPOS — Sheehan Lights

A local-first C# ASP.NET Core + SQLite business management system for **@Sheehan_Lights**, a shop that sells lights and electrical tools.

## Current tested release

The system currently includes:

- Dark responsive dashboard
- Owner and Employee accounts
- Secure password hashing, temporary-password change and account lockout
- Owner-only staff management
- Owner-only expenses, settings and sensitive financial information
- Owner-only product creation, deletion and manual stock adjustment
- Employee read-only sales reports for Today, This Week, This Month and All Time
- Multi-item POS
- Cash, M-Pesa, Card and Bank payment methods
- Discounts
- Automatic stock reduction after every completed sale
- Low-stock visibility
- Product catalogue with SKU/category
- Customer records
- Invoice/receipt generation
- Printable receipts
- Customer WhatsApp invoice sharing
- Copy/WhatsApp business reports
- Owner-only audit log for sensitive business actions
- SQLite local database
- Automatic timestamped database backups on application startup, retaining the latest 14 backups
- Security headers and same-origin protection for state-changing browser requests

## Technology

- C# / ASP.NET Core 10
- Microsoft.Data.Sqlite 10.0.12
- SQLite native library package 3.53.3
- Responsive HTML/CSS/JavaScript

## Run locally

```cmd
git clone https://github.com/AlbisnessTz/HybridBusinessPOS..git
cd HybridBusinessPOS.
dotnet restore
dotnet run
```

Open the local URL shown by ASP.NET Core.

On first run, the system creates the database automatically and seeds starter products if the database is empty.

Database backups are stored in the `backups` folder beside the application database.

## Roles

**Owner**
- Full business control
- Products and stock adjustments
- Expenses
- Reports and financial information
- Staff accounts
- Settings
- Audit Log

**Employee**
- Create sales
- View products and available stock
- Add customers
- View sales reports
- View invoices/receipts
- Cannot manually change stock or access owner-only financial/admin areas

## Important security note

The application is hardened for local/private use, but public Internet deployment still requires a properly configured HTTPS host, firewall/reverse-proxy setup, secure server administration and operational backup procedures.

## Branding

**Shop:** Sheehan Lights  
**Developer:** Albert Mamuya / AlbisnessTz  
**Phone:** +255 756 215 162  
**Email:** AlbisnessTz@gmail.com  
**Social:** @AlbisnessTz
