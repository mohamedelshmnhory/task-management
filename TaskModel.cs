using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;

/// <summary>
/// Represents a task belonging to a project and assigned to a user.
/// </summary>
public class Task
{
    public int Id { get; set; }
    [Required, StringLength(200)]
    public string Title { get; set; }
    public string? Description { get; set; }
    public int ProjectId { get; set; }
    public Project Project { get; set; }
    public int? AssignedUserId { get; set; }
    public User? AssignedUser { get; set; }
    public TaskStatus Status { get; set; }
    public ICollection<Comment> Comments { get; set; }
}

public enum TaskStatus
{
    Todo,
    InProgress,
    Done
} 