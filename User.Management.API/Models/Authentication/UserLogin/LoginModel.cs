﻿using System.ComponentModel.DataAnnotations;

namespace User.Management.API.Models.Authentication.UserLogin
{
    public class LoginModel
    {
        [Required(ErrorMessage = "User Name is Required")]

        public string? UserName { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        public string? Password { get; set; }

    }
}
