$(document).ready(function () {
    // Initialize password strength meter
    function updatePasswordStrength(password) {
        const strengthMeter = $('.password-strength');
        const strength = calculatePasswordStrength(password);
        
        strengthMeter.removeClass('bg-danger bg-warning bg-info bg-success');
        let strengthClass = '';
        let strengthText = '';

        if (strength >= 80) {
            strengthClass = 'bg-success';
            strengthText = 'Strong';
        } else if (strength >= 60) {
            strengthClass = 'bg-info';
            strengthText = 'Good';
        } else if (strength >= 40) {
            strengthClass = 'bg-warning';
            strengthText = 'Moderate';
        } else {
            strengthClass = 'bg-danger';
            strengthText = 'Weak';
        }

        strengthMeter.html(`
            <div class="progress">
                <div class="progress-bar ${strengthClass}" role="progressbar" 
                     style="width: ${strength}%" aria-valuenow="${strength}" 
                     aria-valuemin="0" aria-valuemax="100">
                    ${strengthText}
                </div>
            </div>
        `);
    }

    function calculatePasswordStrength(password) {
        let strength = 0;
        
        // Length
        if (password.length >= 12) {
            strength += 25;
        } else if (password.length >= 8) {
            strength += 10;
        }

        // Contains lowercase letters
        if (password.match(/[a-z]/)) {
            strength += 15;
        }

        // Contains uppercase letters
        if (password.match(/[A-Z]/)) {
            strength += 15;
        }

        // Contains numbers
        if (password.match(/\d/)) {
            strength += 15;
        }

        // Contains special characters
        if (password.match(/[^A-Za-z0-9]/)) {
            strength += 15;
        }

        // Variety of characters
        const uniqueChars = new Set(password).size;
        strength += Math.min(15, uniqueChars);

        return Math.min(100, strength);
    }

    // Password generator
    function generatePassword() {
        const length = 16;
        const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let password = "";
        
        // Ensure at least one of each required character type
        password += getRandomChar("abcdefghijklmnopqrstuvwxyz");
        password += getRandomChar("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        password += getRandomChar("0123456789");
        password += getRandomChar("!@#$%^&*()_+-=[]{}|;:,.<>?");

        // Fill the rest with random characters
        for (let i = password.length; i < length; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }

        // Shuffle the password
        password = password.split('').sort(() => Math.random() - 0.5).join('');
        
        return password;
    }

    function getRandomChar(charset) {
        return charset.charAt(Math.floor(Math.random() * charset.length));
    }

    // Search and filter functionality
    $('#searchInput').on('input', function() {
        const searchTerm = $(this).val().toLowerCase();
        filterPasswords();
    });

    $('#categoryFilter').on('change', function() {
        filterPasswords();
    });

    function filterPasswords() {
        const searchTerm = $('#searchInput').val().toLowerCase();
        const category = $('#categoryFilter').val();

        $('#passwordTable tbody tr').each(function() {
            const row = $(this);
            const title = row.find('td:first').text().toLowerCase();
            const username = row.find('td:eq(1)').text().toLowerCase();
            const website = row.find('td:eq(2)').text().toLowerCase();
            const rowCategory = row.data('category');

            const matchesSearch = title.includes(searchTerm) || 
                                username.includes(searchTerm) || 
                                website.includes(searchTerm);
            const matchesCategory = !category || rowCategory === category;

            row.toggle(matchesSearch && matchesCategory);
        });
    }

    // Password visibility toggle
    $('.toggle-password').click(function() {
        const passwordInput = $('#password');
        const icon = $(this).find('i');

        if (passwordInput.attr('type') === 'password') {
            passwordInput.attr('type', 'text');
            icon.removeClass('fa-eye').addClass('fa-eye-slash');
        } else {
            passwordInput.attr('type', 'password');
            icon.removeClass('fa-eye-slash').addClass('fa-eye');
        }
    });

    // Generate password
    $('.generate-password').click(function() {
        const password = generatePassword();
        $('#password').val(password).trigger('input');
    });

    // Password strength meter
    $('#password').on('input', function() {
        updatePasswordStrength($(this).val());
    });

    // Copy password to clipboard
    $('.copy-password').click(async function() {
        const passwordId = $(this).data('id');
        try {
            const response = await fetch(`/api/passwords/${passwordId}/decrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });

            if (response.ok) {
                const { password } = await response.json();
                await navigator.clipboard.writeText(password);
                
                const button = $(this);
                const originalHtml = button.html();
                button.html('<i class="fas fa-check"></i>');
                setTimeout(() => button.html(originalHtml), 1500);
            }
        } catch (error) {
            console.error('Failed to copy password:', error);
        }
    });

    // Edit password
    $('.edit-password').click(async function() {
        const passwordId = $(this).data('id');
        try {
            const response = await fetch(`/api/passwords/${passwordId}`);
            if (response.ok) {
                const data = await response.json();
                
                $('#passwordId').val(data.id);
                $('#title').val(data.title);
                $('#username').val(data.username);
                $('#website').val(data.website);
                $('#category').val(data.category);
                $('#notes').val(data.notes);
                
                $('.modal-title').text('Edit Password');
                $('#passwordModal').modal('show');
            }
        } catch (error) {
            console.error('Failed to load password:', error);
        }
    });

    // Delete password
    $('.delete-password').click(async function() {
        if (!confirm('Are you sure you want to delete this password?')) {
            return;
        }

        const passwordId = $(this).data('id');
        try {
            const response = await fetch(`/api/passwords/${passwordId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                $(this).closest('tr').remove();
            }
        } catch (error) {
            console.error('Failed to delete password:', error);
        }
    });

    // Form submission
    $('#passwordForm').on('submit', async function(e) {
        e.preventDefault();

        if (!$(this).valid()) {
            return;
        }

        const formData = new FormData(this);
        const data = Object.fromEntries(formData.entries());

        try {
            const response = await fetch('/api/passwords', {
                method: data.Id ? 'PUT' : 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });

            if (response.ok) {
                $('#passwordModal').modal('hide');
                window.location.reload();
            }
        } catch (error) {
            console.error('Failed to save password:', error);
        }
    });
});
