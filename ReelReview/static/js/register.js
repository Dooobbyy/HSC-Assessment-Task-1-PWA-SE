document.addEventListener("DOMContentLoaded", function() {
  var registerForm = document.getElementById("registerForm");
  if (registerForm) {
    registerForm.addEventListener("submit", function(e) {
      var password = document.getElementById("password").value;
      var passwordConfirm = document.getElementById("password_confirm").value;
      var errorSpan = document.getElementById("password_error");
      
      if (password !== passwordConfirm) {
        e.preventDefault();
        errorSpan.textContent = "Passwords do not match!";
      } else {
        errorSpan.textContent = "";
      }
    });
  }
});
