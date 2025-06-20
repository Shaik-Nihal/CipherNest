document.addEventListener('DOMContentLoaded', function() {

    // --- Helper function to display alerts ---
    function showAlert(alertContainerId, message, type = 'danger') {
        const alertContainer = document.getElementById(alertContainerId);
        if (alertContainer) {
            const alertTypeClass = type === 'success' ? 'alert-success' : 'alert-danger';
            const icon = type === 'success' ? '✅' : '⚠️';
            alertContainer.innerHTML = `<div class="alert ${alertTypeClass} alert-dismissible fade show" role="alert">
                                            ${icon} ${message}
                                            <button type="button" class="close" data-dismiss="alert" aria-label="Close">
                                                <span aria-hidden="true">&times;</span>
                                            </button>
                                        </div>`;
        }
    }

    // --- Helper function to clear alerts ---
    function clearAlerts(alertContainerId) {
        const alertContainer = document.getElementById(alertContainerId);
        if (alertContainer) {
            alertContainer.innerHTML = '';
        }
    }

    // --- Message Size Estimation Logic ---
    const EST_SALT_SIZE = 16;
    const EST_IV_SIZE = 16;
    const EST_AES_BLOCK_SIZE = 16;
    const EST_LENGTH_HEADER_BITS = 32;

    function estimateRequiredBits(messageString) {
        if (!messageString) return 0;
        const utf8ByteLength = new TextEncoder().encode(messageString).length;
        const paddedAesLength = (Math.floor(utf8ByteLength / EST_AES_BLOCK_SIZE) + 1) * EST_AES_BLOCK_SIZE;
        const totalEncryptedBytes = EST_SALT_SIZE + EST_IV_SIZE + paddedAesLength;
        const base64Length = Math.ceil(totalEncryptedBytes / 3) * 4;
        const totalBits = (base64Length * 8) + EST_LENGTH_HEADER_BITS;
        return totalBits;
    }

    function getImageCapacity(imageFile, callback) {
        if (!imageFile) { callback(0); return; }
        const reader = new FileReader();
        reader.onload = function(e) {
            const img = new Image();
            img.onload = function() {
                const capacityInBits = img.width * img.height * 3;
                callback(capacityInBits);
            };
            img.onerror = function() { callback(0); };
            img.src = e.target.result;
        };
        reader.onerror = function() { callback(0); };
        reader.readAsDataURL(imageFile);
    }

    function updateSizeEstimation() {
        const encodeFormTest = document.getElementById('encodeForm');
        if (!encodeFormTest) return;
        const messageInput = document.getElementById('message');
        const imageInput = document.getElementById('imageFile');
        const estimateDisplay = document.getElementById('sizeEstimateDisplay');
        const submitButton = document.querySelector('#encodeForm button[type="submit"]');
        if (!messageInput || !imageInput || !estimateDisplay) return;

        const message = messageInput.value;
        const imageFile = imageInput.files && imageInput.files.length > 0 ? imageInput.files[0] : null;

        if (submitButton && typeof submitButton.dataset.originallyDisabled === 'undefined') {
            submitButton.dataset.originallyDisabled = submitButton.disabled.toString();
        }
        const originallyDisabled = submitButton ? submitButton.dataset.originallyDisabled === 'true' : false;

        if (message && imageFile) {
            const requiredBits = estimateRequiredBits(message);
            getImageCapacity(imageFile, function(capacityInBits) {
                if (capacityInBits === 0) {
                    estimateDisplay.innerHTML = '⚠️ Could not determine image capacity. Please select a valid PNG image.';
                    estimateDisplay.className = 'size-estimate-display text-warning';
                    if (submitButton) { submitButton.disabled = true; submitButton.dataset.disabledByEstimate = 'true'; }
                    return;
                }
                
                const usagePercent = ((requiredBits / capacityInBits) * 100).toFixed(1);
                let html = `📊 <strong>Capacity Analysis:</strong><br>`;
                html += `Required: ${requiredBits.toLocaleString()} bits | Available: ${capacityInBits.toLocaleString()} bits | Usage: ${usagePercent}%<br>`;
                
                if (requiredBits > capacityInBits) {
                    html += '❌ <strong>Message too large for this image!</strong> Try a larger image or shorter message.';
                    estimateDisplay.className = 'size-estimate-display text-danger';
                    if (submitButton) { submitButton.disabled = true; submitButton.dataset.disabledByEstimate = 'true'; }
                } else {
                    const icon = usagePercent < 50 ? '✅' : usagePercent < 80 ? '⚡' : '⚠️';
                    html += `${icon} <strong>Message will fit perfectly!</strong>`;
                    estimateDisplay.className = 'size-estimate-display text-success';
                    if (submitButton && !originallyDisabled) { submitButton.disabled = false; }
                    submitButton.removeAttribute('data-disabled-by-estimate');
                }
                estimateDisplay.innerHTML = html;
            });
        } else {
            estimateDisplay.innerHTML = '📏 <strong>Size Estimation:</strong><br>Enter message and select image for capacity analysis.';
            estimateDisplay.className = 'size-estimate-display text-muted';
            if (submitButton && submitButton.dataset.disabledByEstimate === 'true' && !originallyDisabled) {
                 submitButton.disabled = false;
                 submitButton.removeAttribute('data-disabledByEstimate');
            } else if (submitButton && originallyDisabled) {
                submitButton.disabled = true;
            }
        }
    }

    // --- Password Strength Meter Logic ---
    function checkPasswordStrength(password) {
        let score = 0; let strength = 'Too weak'; let strengthClass = 'strength-weak';
        if (!password || password.length === 0) { return { text: '', class: '' }; }
        
        // Length scoring
        if (password.length >= 8) score++; 
        if (password.length >= 10) score++; 
        if (password.length >= 12) score++;
        
        // Character variety scoring
        if (/[a-z]/.test(password)) score++; 
        if (/[A-Z]/.test(password)) score++; 
        if (/[0-9]/.test(password)) score++; 
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        
        // Determine strength
        if (score < 3) { 
            strength = 'Weak 🔴'; 
            strengthClass = 'strength-weak'; 
        } else if (score < 5) { 
            strength = 'Fair 🟡'; 
            strengthClass = 'strength-fair'; 
        } else if (score < 7) { 
            strength = 'Good 🟢'; 
            strengthClass = 'strength-good'; 
        } else { 
            strength = 'Strong 💪'; 
            strengthClass = 'strength-strong'; 
        }
        
        // Override for very short passwords
        if (password.length < 8 && score < 4) { 
            strength = 'Too weak ❌'; 
            strengthClass = 'strength-weak'; 
        }
        if (password.length < 6) { 
            strength = 'Too weak ❌'; 
            strengthClass = 'strength-weak'; 
        }
        
        return { text: '🔑 Password Strength: ' + strength, class: strengthClass };
    }

    function setupPasswordStrengthMeter(keyInputId, meterId) {
        const keyInput = document.getElementById(keyInputId);
        const meterElement = document.getElementById(meterId);
        if (!keyInput || !meterElement) return;
        
        keyInput.addEventListener('input', function() {
            const password = keyInput.value; 
            const strengthDetails = checkPasswordStrength(password);
            meterElement.textContent = strengthDetails.text; 
            meterElement.className = 'strength-meter';
            if (strengthDetails.class && strengthDetails.text) { 
                meterElement.classList.add(strengthDetails.class); 
            }
        });
        
        // Initial check
        const initialStrengthDetails = checkPasswordStrength(keyInput.value);
        meterElement.textContent = initialStrengthDetails.text; 
        meterElement.className = 'strength-meter';
        if (initialStrengthDetails.class && initialStrengthDetails.text) { 
            meterElement.classList.add(initialStrengthDetails.class); 
        }
    }

    // --- Drag and Drop Functionality ---
    function setupDragAndDrop(dropZoneId, fileInputId, fileNameDisplayId, alertContainerId) {
        const dropZone = document.getElementById(dropZoneId);
        const fileInput = document.getElementById(fileInputId);
        const fileNameDisplay = document.getElementById(fileNameDisplayId);
        if (!dropZone || !fileInput) return;
        
        dropZone.addEventListener('click', () => { fileInput.click(); });
        
        fileInput.addEventListener('change', () => {
            const previewElementId = dropZoneId.includes('encode') ? 'originalImagePreview' : 'decodeImagePreview';
            const previewElement = document.getElementById(previewElementId);
            const placeholderId = dropZoneId.includes('encode') ? 'originalPlaceholder' : 'decodePlaceholder';
            const placeholder = document.getElementById(placeholderId);
            
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                if (file.type === 'image/png') {
                    if(fileNameDisplay) {
                        fileNameDisplay.innerHTML = `📁 <strong>Selected:</strong> ${file.name} <span class="text-success">(${(file.size / 1024 / 1024).toFixed(2)} MB)</span>`;
                    }
                    clearAlerts(alertContainerId);
                    
                    if (previewElement) {
                        const reader = new FileReader();
                        reader.onload = function(e) { 
                            previewElement.src = e.target.result; 
                            previewElement.style.display = 'block';
                            if (placeholder) placeholder.style.display = 'none';
                        }
                        reader.readAsDataURL(file);
                    }
                    if (dropZoneId.includes('encode')) { updateSizeEstimation(); }
                } else {
                    showAlert(alertContainerId, 'Invalid file type! Please upload a PNG image only.', 'danger');
                    fileInput.value = '';
                    if(fileNameDisplay) fileNameDisplay.innerHTML = '';
                    if(previewElement) { 
                        previewElement.src = '#'; 
                        previewElement.style.display = 'none'; 
                    }
                    if(placeholder) placeholder.style.display = 'block';
                    if (dropZoneId.includes('encode')) { updateSizeEstimation(); }
                }
            } else {
                 if(fileNameDisplay) fileNameDisplay.innerHTML = '';
                 if(previewElement) { 
                     previewElement.src = '#'; 
                     previewElement.style.display = 'none'; 
                 }
                 if(placeholder) placeholder.style.display = 'block';
                 if (dropZoneId.includes('encode')) { updateSizeEstimation(); }
            }
        });
        
        dropZone.addEventListener('dragover', (event) => { 
            event.preventDefault(); 
            dropZone.classList.add('dragover'); 
        });
        
        dropZone.addEventListener('dragleave', () => { 
            dropZone.classList.remove('dragover'); 
        });
        
        dropZone.addEventListener('drop', (event) => {
            event.preventDefault(); 
            dropZone.classList.remove('dragover');
            clearAlerts(alertContainerId);
            
            const files = event.dataTransfer.files;
            if (files.length === 1) {
                if (files[0].type === 'image/png') {
                    fileInput.files = files;
                    const changeEvent = new Event('change', { bubbles: true });
                    fileInput.dispatchEvent(changeEvent);
                } else {
                    showAlert(alertContainerId, 'Invalid file type! Please drop a PNG image only.', 'danger');
                    if(fileNameDisplay) fileNameDisplay.innerHTML = '';
                }
            } else if (files.length > 1) { 
                showAlert(alertContainerId, 'Please drop only one file at a time.', 'danger');
            }
            
            if(fileNameDisplay && (!files || files.length === 0 || (files.length > 0 && files[0].type !== 'image/png'))) {
                 if(fileNameDisplay) fileNameDisplay.innerHTML = '';
            }
        });
    }

    // --- Encode Page Logic ---
    const encodeForm = document.getElementById('encodeForm');
    if (encodeForm) {
        setupDragAndDrop('encodeDropZone', 'imageFile', 'encodeFileName', 'encodeAlerts');
        setupPasswordStrengthMeter('key', 'keyStrengthMeterEncode');
        
        const messageInputForEstimate = document.getElementById('message');
        if (messageInputForEstimate) {
            messageInputForEstimate.addEventListener('input', updateSizeEstimation);
        }
        updateSizeEstimation();

        const loadingOverlayEncode = document.getElementById('loadingOverlayEncode');

        encodeForm.addEventListener('submit', function(event) {
            event.preventDefault();
            clearAlerts('encodeAlerts');
            
            const encodedImagePreview = document.getElementById('encodedImagePreview');
            const downloadLinkContainer = document.getElementById('downloadLinkContainer');
            const encodedPlaceholder = document.getElementById('encodedPlaceholder');
            
            if(encodedImagePreview) encodedImagePreview.style.display = 'none';
            if(downloadLinkContainer) downloadLinkContainer.style.display = 'none';
            if(encodedPlaceholder) encodedPlaceholder.style.display = 'block';

            const formData = new FormData(encodeForm);
            if (!formData.get('image') || !formData.get('image').name) { 
                showAlert('encodeAlerts', 'Please select an image file first!', 'danger'); 
                return; 
            }
            if (!formData.get('key')) { 
                showAlert('encodeAlerts', 'Encryption key cannot be empty!', 'danger'); 
                return; 
            }
            if (!formData.get('message')) { 
                showAlert('encodeAlerts', 'Message cannot be empty!', 'danger'); 
                return; 
            }

            const submitButton = encodeForm.querySelector('button[type="submit"]');
            const originalButtonText = submitButton.innerHTML;
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 🔐 Encrypting...';

            if(loadingOverlayEncode) loadingOverlayEncode.style.display = 'flex';

            fetch('/api/encode', { method: 'POST', body: formData })
            .then(response => {
                if (response.ok) { return response.blob(); }
                else { return response.json().then(errorData => { throw new Error(errorData.error || 'Encoding failed'); }); }
            })
            .then(imageBlob => {
                const imageUrl = URL.createObjectURL(imageBlob);
                if(encodedImagePreview) { 
                    encodedImagePreview.src = imageUrl; 
                    encodedImagePreview.style.display = 'block'; 
                }
                if(encodedPlaceholder) encodedPlaceholder.style.display = 'none';
                
                const downloadLink = document.getElementById('downloadEncodedImage');
                if(downloadLink) {
                    downloadLink.href = imageUrl;
                    const originalFilename = formData.get('image').name;
                    const base = originalFilename.substring(0, originalFilename.lastIndexOf('.'));
                    const ext = originalFilename.substring(originalFilename.lastIndexOf('.'));
                    downloadLink.download = `${base}_encoded${ext}`;
                }
                if(downloadLinkContainer) downloadLinkContainer.style.display = 'block';
                showAlert('encodeAlerts', 'Message hidden successfully! Your secret is now safely encrypted and embedded in the image.', 'success');
            })
            .catch(error => {
                console.error('Encode: Error during fetch/processing:', error);
                showAlert('encodeAlerts', error.message || 'An unknown error occurred during encoding.', 'danger');
                if(encodedImagePreview) encodedImagePreview.style.display = 'none';
                if(downloadLinkContainer) downloadLinkContainer.style.display = 'none';
                if(encodedPlaceholder) encodedPlaceholder.style.display = 'block';
            })
            .finally(() => {
                const overlayToHide = document.getElementById('loadingOverlayEncode');
                if (overlayToHide) {
                    overlayToHide.style.display = 'none';
                }
                if(submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalButtonText;
                }
                updateSizeEstimation();
            });
        });
    }

    // --- Decode Page Logic ---
    const decodeForm = document.getElementById('decodeForm');
    if (decodeForm) {
        setupDragAndDrop('decodeDropZone', 'imageFile', 'decodeFileName', 'decodeAlerts');
        setupPasswordStrengthMeter('key', 'keyStrengthMeterDecode');

        const loadingOverlayDecode = document.getElementById('loadingOverlayDecode');

        decodeForm.addEventListener('submit', function(event) {
            event.preventDefault();
            clearAlerts('decodeAlerts');
            
            const revealedMessageTextarea = document.getElementById('revealedMessage');
            const revealedMessageContainer = document.getElementById('revealedMessageContainer');
            const messagePlaceholder = document.getElementById('messagePlaceholder');
            
            if(revealedMessageContainer) revealedMessageContainer.style.display = 'none';
            if(revealedMessageTextarea) revealedMessageTextarea.value = '';
            if(messagePlaceholder) messagePlaceholder.style.display = 'block';

            const formData = new FormData(decodeForm);
            if (!formData.get('image') || !formData.get('image').name) { 
                showAlert('decodeAlerts', 'Please select an encoded image file first!', 'danger'); 
                return; 
            }
            if (!formData.get('key')) { 
                showAlert('decodeAlerts', 'Decryption key cannot be empty!', 'danger'); 
                return; 
            }

            const submitButton = decodeForm.querySelector('button[type="submit"]');
            const originalButtonText = submitButton.innerHTML;
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 🔍 Decrypting...';

            if(loadingOverlayDecode) loadingOverlayDecode.style.display = 'flex';

            fetch('/api/decode', { method: 'POST', body: formData })
            .then(response => {
                return response.json();
            })
            .then(data => {
                if (data.error) { throw new Error(data.error); }
                if (data.message) {
                    if(revealedMessageTextarea) revealedMessageTextarea.value = data.message;
                    if(revealedMessageContainer) revealedMessageContainer.style.display = 'block';
                    if(messagePlaceholder) messagePlaceholder.style.display = 'none';
                    showAlert('decodeAlerts', 'Secret message revealed successfully! Your hidden message has been decrypted and extracted.', 'success');
                } else { 
                    throw new Error('Unexpected response from server.'); 
                }
            })
            .catch(error => {
                console.error('Decode: Error during fetch/processing:', error);
                showAlert('decodeAlerts', error.message || 'An unknown error occurred during decoding.', 'danger');
                if(revealedMessageContainer) revealedMessageContainer.style.display = 'none';
                if(messagePlaceholder) messagePlaceholder.style.display = 'block';
            })
            .finally(() => {
                const overlayToHide = document.getElementById('loadingOverlayDecode');
                if (overlayToHide) {
                    overlayToHide.style.display = 'none';
                }
                if(submitButton) {
                    submitButton.disabled = false;
                    submitButton.innerHTML = originalButtonText;
                }
            });
        });
    }

    // Add some entrance animations
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
        card.style.animationDelay = `${index * 0.1}s`;
        card.classList.add('fade-in');
    });
});