* Register (Admin, Doctor, Patient)
- If successfully registered or created -> User Created and Email Sent to (Your EMAIL) Successfully.
* Login 
- If successfully login (sent an OTP to your email),
* Login with 2FA (Copy the code/OTP)
- If your OTP is correct (you can see the token)
* Authorization (So far, admin pa lang ang authorized) {Copy the token)
* Forgot Password (You will receive an email if the email you put is already in the database/registered.
- Password Changed Request is Sent to your Email. Please open your Email and click the link
- Copy the Token 
* Reset Password
- Provide new password/confirmpassword, your email, and the token you copied.
- Password has been updated.

Note: So far, No UI
* On appsetting.json there's a comment: Please follow.
* If you successfully connect your database...
* Update the database using this command on the package Manager console. "update-database"
