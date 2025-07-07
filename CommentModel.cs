using System;
using System.ComponentModel.DataAnnotations;

public class Comment
{
    public int Id { get; set; }
    [Required]
    public string Text { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public int TaskId { get; set; }
    public Task Task { get; set; }

    public int UserId { get; set; }
    public User User { get; set; }
}