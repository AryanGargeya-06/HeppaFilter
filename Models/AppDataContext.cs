using Microsoft.EntityFrameworkCore;

namespace BESAFE.Models
{
    public class AppDataContext : DbContext
    {
        public AppDataContext(DbContextOptions<AppDataContext> options): 
            base(options)
                { }
            public DbSet<product>product { get; set; }  
    }
}
