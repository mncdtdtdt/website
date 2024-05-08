const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');

registerBtn.addEventListener('click', () => {
    container.classList.add("active");
});

loginBtn.addEventListener('click', () => {
    container.classList.remove("active");
});

function onChange(control, oldValue, newValue, isLoading, isTemplate) {
  var originalValue = g_form.getValue("end_date");
  if (isLoading || newValue === '' || originalValue === '') {
    return;
  }

  if (new Date(newValue) > new Date(originalValue)) {
    const alertContainer = document.querySelector('.alert-container');
    const alertMessage = document.createElement('div');
    alertMessage.classList.add('alert');
    alertMessage.textContent = 'End date cannot be greater than start date.';
    alertContainer.appendChild(alertMessage);

    setTimeout(() => {
      alertMessage.style.animation = 'alert-animation 0.5s ease-out forwards';
      setTimeout(() => {
        alertContainer.removeChild(alertMessage);
      }, 500);
    }, 5000);
  }
}