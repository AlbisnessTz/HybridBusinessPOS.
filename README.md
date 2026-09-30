# HybridBusinessPOS — Sheehan Lights

A simple C# ASP.NET Core + SQLite business management system being built for **@Sheehan_Lights**, a shop that sells lights and electrical tools.

## Current version

This first practical MVP focuses on the daily shop workflow:

- Dark responsive dashboard
- Product catalogue
- Buying and selling prices
- Opening stock
- Stock in / stock out adjustment
- Low-stock visibility
- Quick POS sale
- Cash, M-Pesa, Card and Bank payment options
- Discounts
- Automatic stock reduction after a sale
- Invoice number generation
- Sales history / reports
- Shop settings
- Local SQLite database
- Starter products for a lighting/electrical shop

## Technology

- C# / ASP.NET Core 8
- Microsoft.Data.Sqlite
- SQLite
- Responsive HTML/CSS

## Run locally

git clone https://github.com/AlbisnessTz/HybridBusinessPOS..git
cd HybridBusinessPOS.
dotnet restore
dotnet run

Open the local URL shown by ASP.NET Core.

On first run, the system creates the database file automatically and seeds starter products if the database is empty.

## Next development phases

The project can be expanded with customer records, barcode scanning, printable receipts, user login/roles, expenses, richer reports, backups, cloud synchronization and a more advanced multi-item POS cart.

## Branding

**Shop:** Sheehan Lights  
**Developer:** Albert Mamuya / AlbisnessTz  
**Phone:** +255 756 215 162  
**Email:** AlbisnessTz@gmail.com  
**Social:** @AlbisnessTz
