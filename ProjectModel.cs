using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

/// <summary>
/// Represents a project which can have multiple tasks and an owner.
/// </summary>
public class Project
{
    public int Id { get; set; }
    [Required, StringLength(100)]
    public string Name { get; set; }
    public string? Description { get; set; }
    public int OwnerId { get; set; }
    public User Owner { get; set; }
    public ICollection<Task> Tasks { get; set; }
    public ICollection<User> Members { get; set; } // For collaboration
}