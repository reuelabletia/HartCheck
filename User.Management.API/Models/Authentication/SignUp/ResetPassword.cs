﻿using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.SignUp
{
    public class ResetPassword
    {
        [Required]
        public string Password { get; set; } = null!;

        [Compare("Password", ErrorMessage = "The Password and Confirmation Password Do Not Match.")]
        public string ConfirmPassword { get; set; } = null!;

        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
