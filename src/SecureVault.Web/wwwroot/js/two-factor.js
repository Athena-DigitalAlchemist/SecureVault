document.addEventListener('DOMContentLoaded', function () {
    loadTwoFactorStatus();

    // Setup button click handler
    document.getElementById('setupButton').addEventListener('click', initiateTwoFactorSetup);
    
    // Disable button click handler
    document.getElementById('disableButton').addEventListener('click', disableTwoFactor);
    
    // Verify button click handler
    document.getElementById('verifyButton').addEventListener('click', verifySetup);
    
    // Copy recovery codes button click handler
    document.getElementById('copyRecoveryCodesButton').addEventListener('click', copyRecoveryCodes);
});

async function loadTwoFactorStatus() {
    try {
        const response = await fetch('/api/TwoFactorAuth/status');
        const data = await response.json();
        
        const statusBadge = document.getElementById('statusBadge');
        const setupButton = document.getElementById('setupButton');
        const disableButton = document.getElementById('disableButton');
        
        if (data.enabled) {
            statusBadge.textContent = 'Enabled';
            statusBadge.classList.add('bg-success');
            setupButton.style.display = 'none';
            disableButton.style.display = 'block';
        } else {
            statusBadge.textContent = 'Disabled';
            statusBadge.classList.add('bg-warning');
            setupButton.style.display = 'block';
            disableButton.style.display = 'none';
        }
    } catch (error) {
        showError('Error loading 2FA status');
        console.error('Error:', error);
    }
}

async function initiateTwoFactorSetup() {
    try {
        const response = await fetch('/api/TwoFactorAuth/setup');
        const setupInfo = await response.json();
        
        // Show setup section
        document.getElementById('setupSection').style.display = 'block';
        
        // Generate QR code
        const qrCode = document.getElementById('qrCode');
        qrCode.innerHTML = '';
        new QRCode(qrCode, {
            text: setupInfo.qrCodeUri,
            width: 200,
            height: 200
        });
        
        // Display manual entry key
        document.getElementById('manualKey').textContent = setupInfo.manualEntryKey;
        
        // Display recovery codes
        const recoveryCodesContainer = document.getElementById('recoveryCodes').querySelector('pre');
        recoveryCodesContainer.textContent = setupInfo.recoveryCodes.join('\n');
        
    } catch (error) {
        showError('Error initiating 2FA setup');
        console.error('Error:', error);
    }
}

async function verifySetup() {
    const code = document.getElementById('verificationCode').value.trim();
    if (!code) {
        showError('Please enter the verification code');
        return;
    }
    
    try {
        const response = await fetch('/api/TwoFactorAuth/setup/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ code })
        });
        
        if (response.ok) {
            showSuccess('Two-factor authentication enabled successfully');
            document.getElementById('setupSection').style.display = 'none';
            loadTwoFactorStatus();
        } else {
            const error = await response.json();
            showError(error.message || 'Invalid verification code');
        }
    } catch (error) {
        showError('Error verifying 2FA setup');
        console.error('Error:', error);
    }
}

async function disableTwoFactor() {
    if (!confirm('Are you sure you want to disable two-factor authentication? This will make your account less secure.')) {
        return;
    }
    
    try {
        const response = await fetch('/api/TwoFactorAuth/disable', {
            method: 'POST'
        });
        
        if (response.ok) {
            showSuccess('Two-factor authentication disabled successfully');
            loadTwoFactorStatus();
        } else {
            const error = await response.json();
            showError(error.message || 'Error disabling 2FA');
        }
    } catch (error) {
        showError('Error disabling 2FA');
        console.error('Error:', error);
    }
}

async function copyRecoveryCodes() {
    const recoveryCodesText = document.getElementById('recoveryCodes').querySelector('pre').textContent;
    try {
        await navigator.clipboard.writeText(recoveryCodesText);
        showSuccess('Recovery codes copied to clipboard');
    } catch (error) {
        showError('Error copying recovery codes');
        console.error('Error:', error);
    }
}

function showSuccess(message) {
    // You can implement this using your preferred notification system
    alert(message);
}

function showError(message) {
    // You can implement this using your preferred notification system
    alert(message);
}
