using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace Task4.Models {
    public class ApplicationUser: IdentityUser {
        public string Name { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime LoginDate { get; set; }
        [NotMapped]
        public string LockStatus => LockoutEnd != null && LockoutEnd > DateTime.Now ? "Locked" : "Active";
    }
}
