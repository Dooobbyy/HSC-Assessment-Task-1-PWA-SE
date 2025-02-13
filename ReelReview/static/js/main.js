document.addEventListener('DOMContentLoaded', function () {
  var deleteAccountLink = document.getElementById('delete-account');
  if (deleteAccountLink) {
    deleteAccountLink.addEventListener('click', function(e) {
      e.preventDefault();
      if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        document.getElementById('deleteForm').submit();
      }
    });
  }
});
