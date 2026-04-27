// CyberGuard Pro - Main JavaScript Functions

document.addEventListener('DOMContentLoaded', function() {
    // Debug: Check if Bootstrap is loaded
    console.log('Bootstrap loaded:', typeof bootstrap !== 'undefined');
    
    // Initialize tooltips if Bootstrap is available
    if (typeof bootstrap !== 'undefined') {
        var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
        
        // Debug: Initialize dropdown manually if needed
        var dropdownToggle = document.getElementById('dropdownMenuButton');
        if (dropdownToggle) {
            console.log('Dropdown button found, initializing...');
            var dropdown = new bootstrap.Dropdown(dropdownToggle);
            console.log('Dropdown initialized successfully');
        }
    } else {
        console.error('Bootstrap is not loaded!');
    }

    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        if (!alert.classList.contains('alert-permanent')) {
            setTimeout(function() {
                if (typeof bootstrap !== 'undefined') {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                }
            }, 5000);
        }
    });

    // Add loading states to form submissions
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.classList.add('loading');
                submitBtn.disabled = true;
                
                // Add spinner
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                
                // Reset after 10 seconds in case of issues
                setTimeout(function() {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                    submitBtn.classList.remove('loading');
                }, 10000);
            }
        });
    });

    // Copy to clipboard functionality
    window.copyToClipboard = function(text, button) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function() {
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                button.classList.add('btn-success');
                button.classList.remove('btn-outline-secondary');
                
                setTimeout(function() {
                    button.innerHTML = originalText;
                    button.classList.remove('btn-success');
                    button.classList.add('btn-outline-secondary');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy text: ', err);
                // Fallback for older browsers
                fallbackCopyTextToClipboard(text, button);
            });
        } else {
            fallbackCopyTextToClipboard(text, button);
        }
    };

    function fallbackCopyTextToClipboard(text, button) {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            const successful = document.execCommand('copy');
            if (successful) {
                const originalText = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                button.classList.add('btn-success');
                
                setTimeout(function() {
                    button.innerHTML = originalText;
                    button.classList.remove('btn-success');
                }, 2000);
            }
        } catch (err) {
            console.error('Fallback: Oops, unable to copy', err);
        }
        
        document.body.removeChild(textArea);
    }

    // Password visibility toggle
    window.togglePasswordVisibility = function(inputId, iconId) {
        const passwordField = document.getElementById(inputId);
        const eyeIcon = document.getElementById(iconId || 'eyeIcon');
        
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            if (eyeIcon) eyeIcon.className = 'fas fa-eye-slash';
        } else {
            passwordField.type = 'password';
            if (eyeIcon) eyeIcon.className = 'fas fa-eye';
        }
    };

    // Enhanced progress bar animations with proper percentage display
    function animateProgressBars() {
        const progressBars = document.querySelectorAll('.progress-bar');
        progressBars.forEach(function(bar) {
            // Get the target score from data attribute or parse from existing content
            let targetScore = bar.getAttribute('data-score');
            
            // If no data-score attribute, try to parse from existing content
            if (!targetScore) {
                const existingContent = bar.textContent.trim();
                if (existingContent.includes('%')) {
                    targetScore = parseInt(existingContent.replace('%', ''));
                } else {
                    // Try to parse from style width
                    const styleWidth = bar.style.width;
                    if (styleWidth && styleWidth.includes('%')) {
                        targetScore = parseInt(styleWidth.replace('%', ''));
                    }
                }
            }
            
            // Convert to number and validate
            targetScore = parseInt(targetScore) || 0;
            
            // Ensure score is within valid range
            if (targetScore < 0 || targetScore > 100) {
                console.warn('Invalid progress bar score:', targetScore, 'Setting to 0');
                targetScore = 0;
            }
            
            // Debug logging
            console.log('Animating progress bar with score:', targetScore);
            
            // Set initial state
            bar.style.width = '0%';
            bar.textContent = '0%';
            
            // Animate to target score
            let currentScore = 0;
            const increment = Math.max(1, targetScore / 40); // Ensure at least 1% increment
            
            const animationInterval = setInterval(function() {
                currentScore += increment;
                
                if (currentScore >= targetScore) {
                    currentScore = targetScore;
                    clearInterval(animationInterval);
                }
                
                const roundedScore = Math.round(currentScore);
                bar.style.width = roundedScore + '%';
                bar.textContent = roundedScore + '%';
                
                // Update data attribute for consistency
                bar.setAttribute('data-score', roundedScore);
            }, 25); // 25ms intervals for smooth animation
        });
    }

    // Call animation function with a slight delay to ensure DOM is ready
    setTimeout(animateProgressBars, 200);

    // Smooth scrolling for anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');
    anchorLinks.forEach(function(link) {
        link.addEventListener('click', function(e) {
            const targetId = this.getAttribute('href');
            if (targetId !== '#') {
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    e.preventDefault();
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            }
        });
    });

    // Card hover effects for touch devices
    const cards = document.querySelectorAll('.card');
    cards.forEach(function(card) {
        card.addEventListener('touchstart', function() {
            this.classList.add('card-touched');
        });
        
        card.addEventListener('touchend', function() {
            const self = this;
            setTimeout(function() {
                self.classList.remove('card-touched');
            }, 150);
        });
    });

    // Form validation enhancements
    const formInputs = document.querySelectorAll('input[required], textarea[required], select[required]');
    formInputs.forEach(function(input) {
        input.addEventListener('blur', function() {
            if (this.value.trim() === '') {
                this.classList.add('is-invalid');
            } else {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
            }
        });

        input.addEventListener('input', function() {
            if (this.classList.contains('is-invalid') && this.value.trim() !== '') {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
            }
        });
    });

    // Password strength indicator for registration
    const passwordInput = document.querySelector('input[name="password"]');
    if (passwordInput && window.location.pathname.includes('/register')) {
        passwordInput.addEventListener('input', function() {
            const password = this.value;
            const strengthIndicator = document.getElementById('password-strength') || createPasswordStrengthIndicator();
            updatePasswordStrength(password, strengthIndicator);
        });
    }

    function createPasswordStrengthIndicator() {
        const indicator = document.createElement('div');
        indicator.id = 'password-strength';
        indicator.className = 'password-strength mt-2';
        indicator.innerHTML = `
            <div class="progress" style="height: 5px;">
                <div class="progress-bar" role="progressbar" style="width: 0%" data-score="0">0%</div>
            </div>
            <small class="text-muted">Password strength: <span class="strength-text">Enter a password</span></small>
        `;
        
        const passwordInput = document.querySelector('input[name="password"]');
        if (passwordInput) {
            passwordInput.parentNode.appendChild(indicator);
        }
        
        return indicator;
    }

    function updatePasswordStrength(password, indicator) {
        const progressBar = indicator.querySelector('.progress-bar');
        const strengthText = indicator.querySelector('.strength-text');
        
        let score = 0;
        let feedback = 'Very Weak';
        let color = 'bg-danger';

        // Calculate score based on password characteristics
        if (password.length >= 8) score += 25;
        if (password.length >= 12) score += 15;
        if (password.length >= 16) score += 10;
        if (/[A-Z]/.test(password)) score += 15;
        if (/[a-z]/.test(password)) score += 15;
        if (/[0-9]/.test(password)) score += 15;
        if (/[^A-Za-z0-9]/.test(password)) score += 15;

        // Ensure score is within bounds
        score = Math.max(0, Math.min(100, score));

        // Determine strength and color
        if (score >= 80) {
            feedback = 'Very Strong';
            color = 'bg-success';
        } else if (score >= 60) {
            feedback = 'Strong';
            color = 'bg-success';
        } else if (score >= 40) {
            feedback = 'Moderate';
            color = 'bg-warning';
        } else if (score >= 20) {
            feedback = 'Weak';
            color = 'bg-warning';
        }

        // Update progress bar
        progressBar.style.width = score + '%';
        progressBar.className = 'progress-bar ' + color;
        progressBar.textContent = score + '%';
        progressBar.setAttribute('data-score', score);
        strengthText.textContent = feedback;
    }

    // URL input validation
    const urlInputs = document.querySelectorAll('input[type="url"]');
    urlInputs.forEach(function(input) {
        input.addEventListener('blur', function() {
            const url = this.value.trim();
            if (url && !isValidUrl(url)) {
                this.classList.add('is-invalid');
                showUrlValidationMessage(this, 'Please enter a valid URL (e.g., https://example.com)');
            } else if (url) {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
                hideUrlValidationMessage(this);
            }
        });
    });

    function isValidUrl(string) {
        try {
            new URL(string.startsWith('http') ? string : 'https://' + string);
            return true;
        } catch (_) {
            return false;
        }
    }

    function showUrlValidationMessage(input, message) {
        hideUrlValidationMessage(input);
        const feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = message;
        feedback.setAttribute('data-url-validation', 'true');
        input.parentNode.appendChild(feedback);
    }

    function hideUrlValidationMessage(input) {
        const existingFeedback = input.parentNode.querySelector('[data-url-validation="true"]');
        if (existingFeedback) {
            existingFeedback.remove();
        }
    }

    // Email validation enhancement
    const emailInputs = document.querySelectorAll('input[type="email"]');
    emailInputs.forEach(function(input) {
        input.addEventListener('blur', function() {
            const email = this.value.trim();
            if (email && !isValidEmail(email)) {
                this.classList.add('is-invalid');
                showEmailValidationMessage(this, 'Please enter a valid email address');
            } else if (email) {
                this.classList.remove('is-invalid');
                this.classList.add('is-valid');
                hideEmailValidationMessage(this);
            }
        });
    });

    function isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    function showEmailValidationMessage(input, message) {
        hideEmailValidationMessage(input);
        const feedback = document.createElement('div');
        feedback.className = 'invalid-feedback';
        feedback.textContent = message;
        feedback.setAttribute('data-email-validation', 'true');
        input.parentNode.appendChild(feedback);
    }

    function hideEmailValidationMessage(input) {
        const existingFeedback = input.parentNode.querySelector('[data-email-validation="true"]');
        if (existingFeedback) {
            existingFeedback.remove();
        }
    }

    // Download button enhancements
    const downloadButtons = document.querySelectorAll('a[href*="download-report"]');
    downloadButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            const originalText = this.innerHTML;
            this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Generating...';
            this.classList.add('disabled');
            
            // Reset after download or timeout
            setTimeout(function() {
                button.innerHTML = originalText;
                button.classList.remove('disabled');
            }, 3000);
        });
    });

    // Security score color updates
    function updateSecurityScoreColors() {
        const scoreElements = document.querySelectorAll('[data-security-score]');
        scoreElements.forEach(function(element) {
            const score = parseInt(element.getAttribute('data-security-score'));
            
            if (score >= 80) {
                element.classList.add('text-success');
            } else if (score >= 60) {
                element.classList.add('text-warning');
            } else {
                element.classList.add('text-danger');
            }
        });
    }

    updateSecurityScoreColors();

    // Lazy loading for images (if any)
    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.dataset.src;
                    img.classList.remove('lazy');
                    imageObserver.unobserve(img);
                }
            });
        });

        document.querySelectorAll('img[data-src]').forEach(img => {
            imageObserver.observe(img);
        });
    }

    // Keyboard navigation improvements
    document.addEventListener('keydown', function(e) {
        // Alt + S for security tools menu
        if (e.altKey && e.key === 's') {
            e.preventDefault();
            const urlChecker = document.querySelector('a[href*="url-checker"]');
            if (urlChecker) urlChecker.focus();
        }
        
        // Alt + D for dashboard
        if (e.altKey && e.key === 'd') {
            e.preventDefault();
            const dashboard = document.querySelector('a[href*="dashboard"]');
            if (dashboard) dashboard.click();
        }
    });

    // Performance monitoring (basic)
    if ('performance' in window) {
        window.addEventListener('load', function() {
            setTimeout(function() {
                const loadTime = performance.timing.loadEventEnd - performance.timing.navigationStart;
                console.log('Page load time:', loadTime + 'ms');
                
                // Log slow loading for potential optimization
                if (loadTime > 3000) {
                    console.warn('Slow page load detected. Consider optimization.');
                }
            }, 0);
        });
    }

    // Auto-save form data (for longer forms)
    const longForms = document.querySelectorAll('form[data-autosave]');
    longForms.forEach(function(form) {
        const formId = form.getAttribute('id') || 'autosave-form';
        
        // Load saved data
        const savedData = localStorage.getItem('autosave-' + formId);
        if (savedData) {
            try {
                const data = JSON.parse(savedData);
                Object.keys(data).forEach(function(key) {
                    const input = form.querySelector(`[name="${key}"]`);
                    if (input && input.type !== 'password') {
                        input.value = data[key];
                    }
                });
            } catch (e) {
                console.warn('Failed to load autosave data:', e);
            }
        }
        
        // Save data on input
        form.addEventListener('input', function(e) {
            if (e.target.type !== 'password') {
                const formData = new FormData(form);
                const data = {};
                for (let [key, value] of formData.entries()) {
                    if (form.querySelector(`[name="${key}"]`).type !== 'password') {
                        data[key] = value;
                    }
                }
                localStorage.setItem('autosave-' + formId, JSON.stringify(data));
            }
        });
        
        // Clear saved data on successful submit
        form.addEventListener('submit', function() {
            localStorage.removeItem('autosave-' + formId);
        });
    });

    // Accessibility improvements
    const focusableElements = document.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    
    // Skip to main content functionality
    const skipLink = document.createElement('a');
    skipLink.href = '#main-content';
    skipLink.textContent = 'Skip to main content';
    skipLink.className = 'sr-only sr-only-focusable btn btn-primary position-absolute';
    skipLink.style.top = '10px';
    skipLink.style.left = '10px';
    skipLink.style.zIndex = '9999';
    document.body.insertBefore(skipLink, document.body.firstChild);

    // High contrast mode detection
    if (window.matchMedia && window.matchMedia('(prefers-contrast: high)').matches) {
        document.body.classList.add('high-contrast');
    }

    // Reduced motion preference
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        document.body.classList.add('reduced-motion');
        // Disable animations for users who prefer reduced motion
        const style = document.createElement('style');
        style.textContent = `
            .reduced-motion * {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        `;
        document.head.appendChild(style);
    }
});

// Global utility functions
window.CyberGuardPro = {
    // Show notification
    showNotification: function(message, type = 'info') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        alertDiv.style.top = '20px';
        alertDiv.style.right = '20px';
        alertDiv.style.zIndex = '9999';
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.body.appendChild(alertDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(function() {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    },
    
    // Format security score
    formatSecurityScore: function(score) {
        if (score >= 80) return { level: 'Excellent', class: 'success' };
        if (score >= 60) return { level: 'Good', class: 'warning' };
        if (score >= 40) return { level: 'Fair', class: 'warning' };
        return { level: 'Poor', class: 'danger' };
    },
    
    // Validate form before submission
    validateForm: function(form) {
        const requiredFields = form.querySelectorAll('[required]');
        let isValid = true;
        
        requiredFields.forEach(function(field) {
            if (!field.value.trim()) {
                field.classList.add('is-invalid');
                isValid = false;
            } else {
                field.classList.remove('is-invalid');
                field.classList.add('is-valid');
            }
        });
        
        return isValid;
    }
};
