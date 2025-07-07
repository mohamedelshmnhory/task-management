using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

/// <summary>
/// Represents a user with authentication and profile information.
/// </summary>
public class User
{
    public int Id { get; set; }
    [Required, StringLength(100)]
    public string UserName { get; set; }
    [Required, StringLength(100)]
    public string Email { get; set; }
    [Required]
    public string PasswordHash { get; set; }
    public string? FullName { get; set; }
    public ICollection<Project> Projects { get; set; }
    public ICollection<Task> AssignedTasks { get; set; }
    public ICollection<Comment> Comments { get; set; }
} 