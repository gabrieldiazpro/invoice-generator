/**
 * Peoples Post - Invoice Generator Frontend
 */

// State
let currentFileId = null;
let currentBatchId = null;
let shippersData = [];
let invoicesData = [];

// DOM Elements
const uploadZone = document.getElementById('upload-zone');
const fileInput = document.getElementById('file-input');
const uploadProgress = document.getElementById('upload-progress');

const stepUpload = document.getElementById('step-upload');
const stepPreview = document.getElementById('step-preview');
const stepConfig = document.getElementById('step-config');
const stepResults = document.getElementById('step-results');

const summaryStats = document.getElementById('summary-stats');
const shippersList = document.getElementById('shippers-list');
const invoicesList = document.getElementById('invoices-list');
const clientsGrid = document.getElementById('clients-grid');

const clientModal = document.getElementById('client-modal');
const clientForm = document.getElementById('client-form');

const emailResultsModal = document.getElementById('email-results-modal');

// ==========================================================================
// Navigation
// ==========================================================================

document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const tabId = link.dataset.tab;

        // Update nav
        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');

        // Update content
        document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
        document.getElementById(`tab-${tabId}`).classList.add('active');

        // Load data for tab
        if (tabId === 'clients') {
            loadClients();
        } else if (tabId === 'settings') {
            loadEmailConfig();
        } else if (tabId === 'history') {
            loadHistory();
        } else if (tabId === 'users') {
            loadUsers();
        }
    });
});

// ==========================================================================
// File Upload
// ==========================================================================

uploadZone.addEventListener('click', () => fileInput.click());

uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.classList.add('dragover');
});

uploadZone.addEventListener('dragleave', () => {
    uploadZone.classList.remove('dragover');
});

uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');

    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileUpload(files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileUpload(e.target.files[0]);
    }
});

async function handleFileUpload(file) {
    if (!file.name.endsWith('.csv')) {
        showToast('Veuillez sélectionner un fichier CSV', 'error');
        return;
    }

    // Show progress
    uploadZone.classList.add('hidden');
    uploadProgress.classList.remove('hidden');

    const formData = new FormData();
    formData.append('file', file);

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Erreur lors de l\'upload');
        }

        currentFileId = data.file_id;
        shippersData = data.shippers;

        showPreview(data);
        showToast(`${data.total_shippers} clients trouvés`, 'success');

    } catch (error) {
        showToast(error.message, 'error');
        resetUpload();
    }
}

function resetUpload() {
    uploadZone.classList.remove('hidden');
    uploadProgress.classList.add('hidden');
    fileInput.value = '';
}

// ==========================================================================
// Preview
// ==========================================================================

function showPreview(data) {
    // Update stats
    const totalHT = data.shippers.reduce((sum, s) => sum + s.total_ht, 0);
    const totalLines = data.shippers.reduce((sum, s) => sum + s.lines_count, 0);
    const withEmail = data.shippers.filter(s => s.client_email).length;

    summaryStats.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${data.total_shippers}</div>
            <div class="stat-label">Clients</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${totalLines}</div>
            <div class="stat-label">Lignes</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${formatCurrency(totalHT)}</div>
            <div class="stat-label">Total HT estimé</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${withEmail}/${data.total_shippers}</div>
            <div class="stat-label">Avec email</div>
        </div>
    `;

    // Update shippers list
    shippersList.innerHTML = data.shippers.map(shipper => `
        <div class="shipper-item">
            <input type="checkbox" class="shipper-checkbox" data-shipper="${shipper.name}" checked>
            <div class="shipper-info">
                <div class="shipper-name">${shipper.name}</div>
                <div class="shipper-details">${shipper.lines_count} lignes${shipper.client_email ? ' • ' + shipper.client_email : ''}</div>
            </div>
            <div class="shipper-status ${shipper.client_configured ? 'configured' : 'missing'}">
                ${shipper.client_configured ? '✓ Configuré' : '⚠ À configurer'}
            </div>
            <div class="shipper-total">${formatCurrency(shipper.total_ht)} HT</div>
        </div>
    `).join('');

    // Show steps
    stepUpload.classList.add('hidden');
    stepPreview.classList.remove('hidden');
    stepConfig.classList.remove('hidden');
}

// ==========================================================================
// Generation
// ==========================================================================

document.getElementById('btn-back').addEventListener('click', () => {
    stepPreview.classList.add('hidden');
    stepConfig.classList.add('hidden');
    resetUpload();
});

document.getElementById('btn-generate').addEventListener('click', async () => {
    const prefix = document.getElementById('invoice-prefix').value || 'PP';
    const startNumber = parseInt(document.getElementById('invoice-start').value) || 1;

    // Get selected shippers
    const selectedShippers = [];
    document.querySelectorAll('.shipper-checkbox:checked').forEach(cb => {
        selectedShippers.push(cb.dataset.shipper);
    });

    if (selectedShippers.length === 0) {
        showToast('Veuillez sélectionner au moins un client', 'error');
        return;
    }

    const btn = document.getElementById('btn-generate');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Génération en cours...';

    try {
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                file_id: currentFileId,
                prefix: prefix,
                start_number: startNumber,
                shippers: selectedShippers
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Erreur lors de la génération');
        }

        currentBatchId = data.batch_id;
        invoicesData = data.invoices;
        showResults(data);
        showToast(`${data.total_generated} factures générées`, 'success');

    } catch (error) {
        showToast(error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
                <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
            Générer les factures
        `;
    }
});

function showResults(data) {
    renderInvoicesList(data.invoices);
    updateEmailSummary(data.invoices);

    document.getElementById('btn-download-all').onclick = () => {
        window.location.href = `/api/download-all/${data.batch_id}`;
    };

    stepPreview.classList.add('hidden');
    stepConfig.classList.add('hidden');
    stepResults.classList.remove('hidden');
}

function renderInvoicesList(invoices) {
    invoicesList.innerHTML = invoices.map(inv => {
        let emailStatus = '';
        let emailButton = '';

        if (inv.email_sent) {
            emailStatus = '<span class="invoice-email-status sent">✓ Email envoyé</span>';
            emailButton = '<button class="btn btn-send-email btn-sm" disabled>Envoyé</button>';
        } else if (!inv.client_email) {
            emailStatus = '<span class="invoice-email-status no-email">⚠ Pas d\'email</span>';
            emailButton = '<button class="btn btn-send-email btn-sm" disabled>Pas d\'email</button>';
        } else {
            emailStatus = '<span class="invoice-email-status pending">En attente</span>';
            emailButton = `<button class="btn btn-send-email btn-sm" onclick="sendSingleEmail('${inv.invoice_number}')">Envoyer</button>`;
        }

        return `
            <div class="invoice-item" data-invoice="${inv.invoice_number}">
                <div class="invoice-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                </div>
                <div class="invoice-info">
                    <div class="invoice-name">${inv.shipper}</div>
                    <div class="invoice-number">${inv.invoice_number}${inv.client_email ? ' • ' + inv.client_email : ''}</div>
                </div>
                ${emailStatus}
                <div class="invoice-total">${inv.total_ttc_formatted}</div>
                <a href="/api/download/${currentBatchId}/${inv.filename}" class="btn btn-secondary btn-sm">PDF</a>
                ${emailButton}
            </div>
        `;
    }).join('');
}

function updateEmailSummary(invoices) {
    const sent = invoices.filter(i => i.email_sent).length;
    const pending = invoices.filter(i => !i.email_sent && i.client_email).length;
    const noEmail = invoices.filter(i => !i.client_email).length;

    document.getElementById('emails-sent').textContent = sent;
    document.getElementById('emails-pending').textContent = pending;
    document.getElementById('emails-failed').textContent = noEmail;

    document.getElementById('email-summary').classList.remove('hidden');
}

document.getElementById('btn-new-batch').addEventListener('click', () => {
    stepResults.classList.add('hidden');
    stepUpload.classList.remove('hidden');
    document.getElementById('email-summary').classList.add('hidden');
    resetUpload();
    currentFileId = null;
    currentBatchId = null;
    invoicesData = [];
});

// ==========================================================================
// Email Sending
// ==========================================================================

window.sendSingleEmail = async function(invoiceNumber) {
    const btn = event.target;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span>';

    try {
        const response = await fetch(`/api/email/send/${currentBatchId}/${invoiceNumber}`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Email envoyé avec succès', 'success');
            // Update invoice in list
            const inv = invoicesData.find(i => i.invoice_number === invoiceNumber);
            if (inv) {
                inv.email_sent = true;
            }
            renderInvoicesList(invoicesData);
            updateEmailSummary(invoicesData);
        } else {
            showToast(data.error || 'Erreur lors de l\'envoi', 'error');
            btn.disabled = false;
            btn.textContent = originalText;
        }
    } catch (error) {
        showToast('Erreur lors de l\'envoi', 'error');
        btn.disabled = false;
        btn.textContent = originalText;
    }
};

document.getElementById('btn-send-all-emails').addEventListener('click', async () => {
    const btn = document.getElementById('btn-send-all-emails');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Envoi en cours...';

    try {
        const response = await fetch(`/api/email/send-all/${currentBatchId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ only_pending: true })
        });

        const data = await response.json();

        if (data.success) {
            showEmailResults(data.results);
            // Refresh invoices data
            await refreshInvoicesStatus();
        } else {
            showToast(data.error || 'Erreur lors de l\'envoi', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de l\'envoi', 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
                <polyline points="22,6 12,13 2,6"></polyline>
            </svg>
            Envoyer tous les emails
        `;
    }
});

function showEmailResults(results) {
    document.getElementById('email-results-summary').innerHTML = `
        <div class="stat">
            <div class="stat-value success">${results.sent}</div>
            <div class="stat-label">Envoyés</div>
        </div>
        <div class="stat">
            <div class="stat-value warning">${results.skipped}</div>
            <div class="stat-label">Ignorés</div>
        </div>
        <div class="stat">
            <div class="stat-value error">${results.failed}</div>
            <div class="stat-label">Échoués</div>
        </div>
    `;

    document.getElementById('email-results-list').innerHTML = results.details.map(d => {
        let iconClass = 'success';
        let icon = '✓';
        if (d.status === 'failed') {
            iconClass = 'error';
            icon = '✗';
        } else if (d.status === 'skipped') {
            iconClass = 'skipped';
            icon = '–';
        }

        return `
            <div class="email-result-item">
                <div class="email-result-icon ${iconClass}">${icon}</div>
                <div class="email-result-info">
                    <div class="email-result-invoice">${d.invoice_number}</div>
                    <div class="email-result-message">${d.message}</div>
                </div>
            </div>
        `;
    }).join('');

    emailResultsModal.classList.remove('hidden');
}

async function refreshInvoicesStatus() {
    try {
        const response = await fetch(`/api/email/status/${currentBatchId}`);
        const data = await response.json();
        if (data.success) {
            invoicesData = data.invoices;
            renderInvoicesList(invoicesData);
            updateEmailSummary(invoicesData);
        }
    } catch (error) {
        console.error('Error refreshing status:', error);
    }
}

// Close email results modal
document.getElementById('email-modal-close').addEventListener('click', () => {
    emailResultsModal.classList.add('hidden');
});
document.getElementById('btn-close-email-results').addEventListener('click', () => {
    emailResultsModal.classList.add('hidden');
});

// ==========================================================================
// Form Change Tracking
// ==========================================================================

// Store original values for each form
const formOriginalValues = {
    smtp: {},
    sender: {},
    emailTemplates: {}
};

/**
 * Setup form tracking to enable/disable save button based on changes
 */
function setupFormTracking(formId, fieldIds, buttonId, originalValuesKey) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    // Store original values
    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field) {
            formOriginalValues[originalValuesKey][id] = field.value;
        }
    });

    // Add change listeners to all fields
    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field) {
            const eventType = field.tagName === 'TEXTAREA' ? 'input' : 'input';
            field.addEventListener(eventType, () => checkFormChanges(fieldIds, buttonId, originalValuesKey));
        }
    });

    // Initially disable the button (no changes yet)
    markButtonAsSaved(buttonId);
}

/**
 * Check if form has changes compared to original values
 */
function checkFormChanges(fieldIds, buttonId, originalValuesKey) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    let hasChanges = false;

    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field) {
            const originalValue = formOriginalValues[originalValuesKey][id] || '';
            if (field.value !== originalValue) {
                hasChanges = true;
            }
        }
    });

    if (hasChanges) {
        enableSaveButton(buttonId);
    } else {
        markButtonAsSaved(buttonId);
    }
}

/**
 * Mark button as saved (disabled with checkmark)
 */
function markButtonAsSaved(buttonId) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    btn.disabled = true;
    btn.classList.add('btn-saved');

    // Set the saved text based on button type
    const savedTexts = {
        'btn-save-smtp-config': 'Enregistré',
        'btn-save-sender-config': 'Enregistré',
        'btn-save-email-config': 'Enregistré'
    };
    btn.textContent = savedTexts[buttonId] || 'Enregistré';
}

/**
 * Enable save button (changes detected)
 */
function enableSaveButton(buttonId) {
    const btn = document.getElementById(buttonId);
    if (!btn) return;

    btn.disabled = false;
    btn.classList.remove('btn-saved');

    // Set the active text based on button type
    const activeTexts = {
        'btn-save-smtp-config': 'Enregistrer SMTP',
        'btn-save-sender-config': 'Enregistrer mon identité',
        'btn-save-email-config': 'Enregistrer les templates'
    };
    btn.textContent = activeTexts[buttonId] || 'Enregistrer';
}

/**
 * Update original values after successful save
 */
function updateOriginalValues(fieldIds, originalValuesKey) {
    fieldIds.forEach(id => {
        const field = document.getElementById(id);
        if (field) {
            formOriginalValues[originalValuesKey][id] = field.value;
        }
    });
}

// Field IDs for each form
const smtpFieldIds = ['smtp-server', 'smtp-port', 'smtp-username', 'smtp-password'];
const senderFieldIds = ['sender-name', 'sender-email'];
const emailTemplateFieldIds = [
    'email-subject', 'email-template',
    'reminder-1-subject', 'reminder-1-template',
    'reminder-2-subject', 'reminder-2-template',
    'reminder-3-subject', 'reminder-3-template',
    'reminder-4-subject', 'reminder-4-template'
];

// ==========================================================================
// Email Configuration
// ==========================================================================

async function loadEmailConfig() {
    try {
        const response = await fetch('/api/email/config');
        const config = await response.json();

        // SMTP config (super admin only - fields might not exist)
        const smtpServer = document.getElementById('smtp-server');
        const smtpPort = document.getElementById('smtp-port');
        const smtpUsername = document.getElementById('smtp-username');
        const passwordHint = document.getElementById('password-hint');

        if (smtpServer) smtpServer.value = config.smtp_server || '';
        if (smtpPort) smtpPort.value = config.smtp_port || '';
        if (smtpUsername) smtpUsername.value = config.smtp_username || '';
        if (passwordHint) {
            if (config.smtp_password_set) {
                passwordHint.textContent = '✓ Mot de passe configuré (laisser vide pour conserver)';
            } else {
                passwordHint.textContent = '⚠ Mot de passe non configuré';
            }
        }

        // Email templates (shared config)
        document.getElementById('email-subject').value = config.email_subject || '';
        document.getElementById('email-template').value = config.email_template || '';

        // Reminder templates (4 types)
        document.getElementById('reminder-1-subject').value = config.reminder_1_subject || '';
        document.getElementById('reminder-1-template').value = config.reminder_1_template || '';
        document.getElementById('reminder-2-subject').value = config.reminder_2_subject || '';
        document.getElementById('reminder-2-template').value = config.reminder_2_template || '';
        document.getElementById('reminder-3-subject').value = config.reminder_3_subject || '';
        document.getElementById('reminder-3-template').value = config.reminder_3_template || '';
        document.getElementById('reminder-4-subject').value = config.reminder_4_subject || '';
        document.getElementById('reminder-4-template').value = config.reminder_4_template || '';

        // Load user's sender identity
        await loadSenderConfig();

        // Setup form tracking for SMTP (if fields exist)
        if (document.getElementById('smtp-server')) {
            setupFormTracking('smtp-config-form', smtpFieldIds, 'btn-save-smtp-config', 'smtp');
        }

        // Setup form tracking for email templates
        setupFormTracking('email-templates', emailTemplateFieldIds, 'btn-save-email-config', 'emailTemplates');

    } catch (error) {
        showToast('Erreur lors du chargement de la configuration', 'error');
    }
}

async function loadSenderConfig() {
    try {
        const response = await fetch('/api/me');
        const data = await response.json();

        if (data.success && data.user) {
            document.getElementById('sender-name').value = data.user.sender_name || '';
            document.getElementById('sender-email').value = data.user.sender_email || '';
        }

        // Setup form tracking for sender identity
        setupFormTracking('sender-config-form', senderFieldIds, 'btn-save-sender-config', 'sender');

    } catch (error) {
        console.error('Error loading sender config:', error);
    }
}

// Save email templates (available to all users)
document.getElementById('btn-save-email-config').addEventListener('click', async () => {
    const btn = document.getElementById('btn-save-email-config');
    btn.disabled = true;
    btn.classList.remove('btn-saved');
    btn.textContent = 'Enregistrement...';

    const config = {
        email_subject: document.getElementById('email-subject').value,
        email_template: document.getElementById('email-template').value,
        reminder_1_subject: document.getElementById('reminder-1-subject').value,
        reminder_1_template: document.getElementById('reminder-1-template').value,
        reminder_2_subject: document.getElementById('reminder-2-subject').value,
        reminder_2_template: document.getElementById('reminder-2-template').value,
        reminder_3_subject: document.getElementById('reminder-3-subject').value,
        reminder_3_template: document.getElementById('reminder-3-template').value,
        reminder_4_subject: document.getElementById('reminder-4-subject').value,
        reminder_4_template: document.getElementById('reminder-4-template').value
    };

    try {
        const response = await fetch('/api/email/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const data = await response.json();

        if (data.success) {
            showToast('Templates enregistrés', 'success');
            // Update original values and mark as saved
            updateOriginalValues(emailTemplateFieldIds, 'emailTemplates');
            markButtonAsSaved('btn-save-email-config');
        } else {
            showToast(data.error || 'Erreur lors de l\'enregistrement', 'error');
            enableSaveButton('btn-save-email-config');
        }
    } catch (error) {
        showToast('Erreur lors de l\'enregistrement', 'error');
        enableSaveButton('btn-save-email-config');
    }
});

// Save SMTP config (super admin only)
const btnSaveSmtpConfig = document.getElementById('btn-save-smtp-config');
if (btnSaveSmtpConfig) {
    btnSaveSmtpConfig.addEventListener('click', async () => {
        const btn = btnSaveSmtpConfig;
        btn.disabled = true;
        btn.classList.remove('btn-saved');
        btn.textContent = 'Enregistrement...';

        const config = {
            smtp_server: document.getElementById('smtp-server').value,
            smtp_port: parseInt(document.getElementById('smtp-port').value) || 587,
            smtp_username: document.getElementById('smtp-username').value,
            smtp_password: document.getElementById('smtp-password').value
        };

        try {
            const response = await fetch('/api/email/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            const data = await response.json();

            if (data.success) {
                showToast('Configuration SMTP enregistrée', 'success');
                document.getElementById('smtp-password').value = '';
                // Update original values and mark as saved
                updateOriginalValues(smtpFieldIds, 'smtp');
                markButtonAsSaved('btn-save-smtp-config');
            } else {
                showToast(data.error || 'Erreur lors de l\'enregistrement', 'error');
                enableSaveButton('btn-save-smtp-config');
            }
        } catch (error) {
            showToast('Erreur lors de l\'enregistrement', 'error');
            enableSaveButton('btn-save-smtp-config');
        }
    });
}

// Save sender identity (per-user)
const btnSaveSenderConfig = document.getElementById('btn-save-sender-config');
if (btnSaveSenderConfig) {
    btnSaveSenderConfig.addEventListener('click', async () => {
        const btn = btnSaveSenderConfig;
        btn.disabled = true;
        btn.classList.remove('btn-saved');
        btn.textContent = 'Enregistrement...';

        const senderData = {
            sender_name: document.getElementById('sender-name').value,
            sender_email: document.getElementById('sender-email').value
        };

        try {
            const response = await fetch('/api/me/sender', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(senderData)
            });

            const data = await response.json();

            if (data.success) {
                showToast('Identité d\'expéditeur enregistrée', 'success');
                // Update original values and mark as saved
                updateOriginalValues(senderFieldIds, 'sender');
                markButtonAsSaved('btn-save-sender-config');
            } else {
                showToast(data.error || 'Erreur lors de l\'enregistrement', 'error');
                enableSaveButton('btn-save-sender-config');
            }
        } catch (error) {
            showToast('Erreur lors de l\'enregistrement', 'error');
            enableSaveButton('btn-save-sender-config');
        }
    });
}

// ==========================================================================
// Clients Management
// ==========================================================================

async function loadClients() {
    try {
        const response = await fetch('/api/clients');
        const clients = await response.json();

        renderClients(clients);
    } catch (error) {
        showToast('Erreur lors du chargement des clients', 'error');
    }
}

function renderClients(clients) {
    if (Object.keys(clients).length === 0) {
        clientsGrid.innerHTML = `
            <div class="empty-state">
                <p>Aucun client configuré</p>
                <p>Les clients seront ajoutés automatiquement lors de l'import d'un CSV</p>
            </div>
        `;
        return;
    }

    clientsGrid.innerHTML = Object.entries(clients).map(([key, client]) => {
        const isComplete = client.siret && client.siret !== '00000000000000';
        const hasEmail = client.email && client.email.includes('@');
        const safeKey = encodeURIComponent(key);

        return `
            <div class="client-card" data-client-key="${safeKey}">
                <div class="client-card-header">
                    <div>
                        <div class="client-name">${escapeHtml(client.nom)}</div>
                        <div class="client-key">${escapeHtml(key)}</div>
                    </div>
                    <div class="client-actions">
                        <button class="client-action edit" data-action="edit" data-key="${safeKey}" title="Modifier">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                            </svg>
                        </button>
                        <button class="client-action delete" data-action="delete" data-key="${safeKey}" title="Supprimer">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polyline points="3 6 5 6 21 6"></polyline>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="client-details">
                    <p>${escapeHtml(client.adresse)}</p>
                    <p>${escapeHtml(client.code_postal)} ${escapeHtml(client.ville)}, ${escapeHtml(client.pays)}</p>
                    <p>${client.email ? escapeHtml(client.email) : 'Pas d\'email'}</p>
                    <p>SIRET: ${escapeHtml(client.siret)}</p>
                </div>
                <div class="client-status ${isComplete && hasEmail ? 'complete' : 'incomplete'}">
                    ${isComplete && hasEmail ? '✓ Complet' : '⚠ Informations manquantes'}
                </div>
                <div class="client-account-section" data-client-key="${safeKey}">
                    ${renderAccountStatus(key, client.account_status, safeKey)}
                </div>
            </div>
        `;
    }).join('');

    // Attach event listeners for edit/delete buttons
    clientsGrid.querySelectorAll('[data-action="edit"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = decodeURIComponent(btn.dataset.key);
            editClient(key);
        });
    });

    clientsGrid.querySelectorAll('[data-action="delete"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const key = decodeURIComponent(btn.dataset.key);
            deleteClient(key);
        });
    });

    // Attach event listeners for create account buttons
    clientsGrid.querySelectorAll('[data-action="create-account"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const clientKey = btn.dataset.clientKey;
            openCreateAccountModal(clientKey);
        });
    });
}

// Edit client
window.editClient = async function(key) {
    try {
        const response = await fetch('/api/clients');
        const clients = await response.json();
        const client = clients[key];

        if (!client) return;

        document.getElementById('client-key').value = key;
        document.getElementById('client-nom').value = client.nom || '';
        document.getElementById('client-adresse').value = client.adresse || '';
        document.getElementById('client-cp').value = client.code_postal || '';
        document.getElementById('client-ville').value = client.ville || '';
        document.getElementById('client-pays').value = client.pays || 'France';
        document.getElementById('client-email').value = client.email || '';
        document.getElementById('client-siret').value = client.siret || '';

        document.getElementById('modal-title').textContent = `Modifier: ${key}`;
        clientModal.classList.remove('hidden');
    } catch (error) {
        showToast('Erreur lors du chargement du client', 'error');
    }
};

// Delete client
window.deleteClient = async function(key) {
    if (!confirm(`Êtes-vous sûr de vouloir supprimer "${key}" ?`)) {
        return;
    }

    try {
        await fetch(`/api/clients/${encodeURIComponent(key)}`, {
            method: 'DELETE'
        });

        showToast('Client supprimé', 'success');
        loadClients();
    } catch (error) {
        showToast('Erreur lors de la suppression', 'error');
    }
};

// ============================================================================
// Client Account Management
// ============================================================================

let currentClientKey = null;
const createClientAccountModal = document.getElementById('create-client-account-modal');

// Render account status directly (no API call needed)
function renderAccountStatus(clientKey, accountStatus, safeKey) {
    if (!accountStatus) {
        return '<span class="error-text">Statut inconnu</span>';
    }

    if (accountStatus.has_account) {
        const lastLogin = accountStatus.last_login
            ? new Date(accountStatus.last_login).toLocaleDateString('fr-FR')
            : 'Jamais';
        return `
            <div class="account-active">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                <span>Espace client actif</span>
            </div>
            <small class="account-info-text">Dernière connexion: ${lastLogin}</small>
        `;
    } else {
        return `
            <button class="btn btn-sm btn-client-account" data-action="create-account" data-key="${safeKey}" data-client-key="${escapeHtml(clientKey)}">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                    <circle cx="8.5" cy="7" r="4"></circle>
                    <line x1="20" y1="8" x2="20" y2="14"></line>
                    <line x1="23" y1="11" x2="17" y2="11"></line>
                </svg>
                Créer espace client
            </button>
        `;
    }
}

// Open the create account modal
async function openCreateAccountModal(clientKey) {
    currentClientKey = clientKey;

    // Reset modal state
    document.getElementById('client-account-info').classList.remove('hidden');
    document.getElementById('client-account-result').classList.add('hidden');
    document.getElementById('btn-create-client-account').classList.remove('hidden');
    document.getElementById('btn-cancel-client-account').textContent = 'Annuler';
    document.getElementById('send-welcome-email').checked = true;

    // Get client info
    try {
        const response = await fetch('/api/clients');
        const clients = await response.json();
        const client = clients[clientKey];

        if (client) {
            document.getElementById('account-client-name').textContent = client.nom || clientKey;
            document.getElementById('account-client-email').textContent = client.email || 'Non renseigné';

            if (!client.email || !client.email.includes('@')) {
                document.getElementById('btn-create-client-account').disabled = true;
                document.getElementById('client-account-info').innerHTML += `
                    <div class="alert alert-warning">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        <span>Ce client n'a pas d'adresse email valide. Veuillez d'abord modifier les informations du client.</span>
                    </div>
                `;
            } else {
                document.getElementById('btn-create-client-account').disabled = false;
            }
        }
    } catch (error) {
        showToast('Erreur lors du chargement des informations client', 'error');
        return;
    }

    createClientAccountModal.classList.remove('hidden');
}

// Close the create account modal
function closeCreateAccountModal() {
    createClientAccountModal.classList.add('hidden');
    currentClientKey = null;
}

// Create client account
async function createClientAccount() {
    if (!currentClientKey) return;

    const sendWelcome = document.getElementById('send-welcome-email').checked;
    const btn = document.getElementById('btn-create-client-account');

    btn.disabled = true;
    btn.innerHTML = '<span class="loading-small"></span> Création en cours...';

    try {
        const response = await fetch(`/api/clients/${encodeURIComponent(currentClientKey)}/create-account`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                send_welcome_email: sendWelcome
            })
        });

        const data = await response.json();

        if (response.ok && data.success) {
            // Show success
            document.getElementById('client-account-info').classList.add('hidden');
            document.getElementById('client-account-result').classList.remove('hidden');
            document.getElementById('btn-create-client-account').classList.add('hidden');
            document.getElementById('btn-cancel-client-account').textContent = 'Fermer';

            document.getElementById('result-email').textContent = data.email;

            if (data.temp_password) {
                document.getElementById('result-password').textContent = data.temp_password;
                document.getElementById('account-credentials').classList.remove('hidden');
            } else {
                document.getElementById('account-credentials').classList.add('hidden');
            }

            if (data.email_sent) {
                document.getElementById('email-sent-notice').classList.remove('hidden');
            } else {
                document.getElementById('email-sent-notice').classList.add('hidden');
            }

            showToast('Compte client créé avec succès', 'success');

            // Refresh the client list to update the account status
            loadClients();
        } else {
            showToast(data.error || 'Erreur lors de la création du compte', 'error');
            btn.disabled = false;
            btn.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                    <circle cx="8.5" cy="7" r="4"></circle>
                    <line x1="20" y1="8" x2="20" y2="14"></line>
                    <line x1="23" y1="11" x2="17" y2="11"></line>
                </svg>
                Créer le compte
            `;
        }
    } catch (error) {
        showToast('Erreur lors de la création du compte', 'error');
        btn.disabled = false;
        btn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                <circle cx="8.5" cy="7" r="4"></circle>
                <line x1="20" y1="8" x2="20" y2="14"></line>
                <line x1="23" y1="11" x2="17" y2="11"></line>
            </svg>
            Créer le compte
        `;
    }
}

// Event listeners for client account modal
if (createClientAccountModal) {
    document.getElementById('client-account-modal-close').addEventListener('click', closeCreateAccountModal);
    document.getElementById('btn-cancel-client-account').addEventListener('click', closeCreateAccountModal);
    document.getElementById('btn-create-client-account').addEventListener('click', createClientAccount);

    // Close on backdrop click
    createClientAccountModal.querySelector('.modal-backdrop').addEventListener('click', closeCreateAccountModal);
}

// Add new client
document.getElementById('btn-add-client').addEventListener('click', () => {
    document.getElementById('client-key').value = '';
    clientForm.reset();
    document.getElementById('client-pays').value = 'France';
    document.getElementById('modal-title').textContent = 'Nouveau client';
    clientModal.classList.remove('hidden');
});

// Cleanup duplicate clients
async function cleanupDuplicates() {
    console.log('Cleanup duplicates clicked');
    try {
        showToast('Vérification des doublons...', 'info');
        const checkResponse = await fetch('/api/clients/duplicates');
        const checkData = await checkResponse.json();
        console.log('Duplicates response:', checkData);

        if (!checkData.success) {
            showToast(checkData.error || 'Erreur API', 'error');
            return;
        }

        if (checkData.total_groups === 0) {
            showToast('Aucun doublon détecté', 'info');
            return;
        }

        const duplicatesList = checkData.duplicates.map(group =>
            `• ${group.names.join(' / ')} → garder "${group.recommended_keep}"`
        ).join('\n');

        if (!confirm(`${checkData.total_groups} groupe(s) de doublons détecté(s):\n\n${duplicatesList}\n\nSupprimer automatiquement les doublons (garder le plus complet) ?`)) {
            return;
        }

        // Cleanup
        const response = await fetch('/api/clients/cleanup-duplicates', { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
            loadClients();
        } else {
            showToast(data.error || 'Erreur lors du nettoyage', 'error');
        }
    } catch (error) {
        console.error('Cleanup error:', error);
        showToast('Erreur lors de la vérification des doublons', 'error');
    }
}

const btnCleanupDuplicates = document.getElementById('btn-cleanup-duplicates');
if (btnCleanupDuplicates) {
    btnCleanupDuplicates.addEventListener('click', cleanupDuplicates);
    console.log('Cleanup duplicates button listener attached');
} else {
    console.warn('btn-cleanup-duplicates not found');
}

// Modal close
document.getElementById('modal-close').addEventListener('click', closeModal);
document.getElementById('btn-cancel').addEventListener('click', closeModal);
document.querySelector('.modal-backdrop').addEventListener('click', closeModal);

function closeModal() {
    clientModal.classList.add('hidden');
}

// Save client
document.getElementById('btn-save-client').addEventListener('click', async () => {
    const key = document.getElementById('client-key').value;
    const clientName = document.getElementById('client-nom').value;

    // Use existing key or create new one from name
    const clientKey = key || clientName.replace(/\s+/g, '_');

    const clientData = {
        nom: document.getElementById('client-nom').value,
        adresse: document.getElementById('client-adresse').value,
        code_postal: document.getElementById('client-cp').value,
        ville: document.getElementById('client-ville').value,
        pays: document.getElementById('client-pays').value,
        email: document.getElementById('client-email').value,
        siret: document.getElementById('client-siret').value
    };

    try {
        const response = await fetch(`/api/clients/${encodeURIComponent(clientKey)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(clientData)
        });

        if (!response.ok) {
            throw new Error('Erreur lors de la sauvegarde');
        }

        showToast('Client enregistré', 'success');
        closeModal();
        loadClients();
    } catch (error) {
        showToast(error.message, 'error');
    }
});

// ==========================================================================
// History Management
// ==========================================================================

let historyData = [];
let historyFilter = 'all';

async function loadHistory(search = '') {
    try {
        const url = search ? `/api/history?search=${encodeURIComponent(search)}` : '/api/history';
        const response = await fetch(url);
        const data = await response.json();

        if (data.success) {
            historyData = data.history;
            applyHistoryFilter();
        }
    } catch (error) {
        showToast('Erreur lors du chargement de l\'historique', 'error');
    }
}

function applyHistoryFilter() {
    let filtered = historyData;

    if (historyFilter === 'pending') {
        filtered = historyData.filter(inv => inv.payment_status !== 'paid');
    } else if (historyFilter === 'paid') {
        filtered = historyData.filter(inv => inv.payment_status === 'paid');
    }

    renderHistory(filtered);
    updateHistoryStats(historyData);
}

function renderHistory(history) {
    const tbody = document.getElementById('history-tbody');
    const emptyState = document.getElementById('history-empty');
    const tableContainer = document.querySelector('.history-table-container');

    if (!history || history.length === 0) {
        tableContainer.classList.add('hidden');
        emptyState.classList.remove('hidden');
        return;
    }

    tableContainer.classList.remove('hidden');
    emptyState.classList.add('hidden');

    tbody.innerHTML = history.map(inv => {
        const safeId = encodeURIComponent(inv.id);
        const isPaid = inv.payment_status === 'paid';
        const hasEmail = !!inv.client_email;

        // Payment status badge
        const paymentBadge = isPaid
            ? `<span class="payment-badge paid" data-action="toggle-payment" data-id="${safeId}" title="Cliquer pour marquer comme impayée">Payée</span>`
            : `<span class="payment-badge pending" data-action="toggle-payment" data-id="${safeId}" title="Cliquer pour marquer comme payée">Impayée</span>`;

        // Reminder buttons for R1, R2, R3, R4
        const r1Sent = inv.reminder_1_sent;
        const r2Sent = inv.reminder_2_sent;
        const r3Sent = inv.reminder_3_sent;
        const r4Sent = inv.reminder_4_sent;

        const r1Btn = r1Sent
            ? '<button class="reminder-cell-btn sent" disabled title="Envoyée">R1</button>'
            : (isPaid || !hasEmail)
                ? '<button class="reminder-cell-btn r1" disabled title="Non disponible">R1</button>'
                : `<button class="reminder-cell-btn r1" data-action="send-reminder" data-id="${safeId}" data-type="1" title="Envoyer relance 1">R1</button>`;

        const r2Btn = r2Sent
            ? '<button class="reminder-cell-btn sent" disabled title="Envoyée">R2</button>'
            : (isPaid || !hasEmail)
                ? '<button class="reminder-cell-btn r2" disabled title="Non disponible">R2</button>'
                : `<button class="reminder-cell-btn r2" data-action="send-reminder" data-id="${safeId}" data-type="2" title="Envoyer relance 2">R2</button>`;

        const r3Btn = r3Sent
            ? '<button class="reminder-cell-btn sent" disabled title="Envoyée">R3</button>'
            : (isPaid || !hasEmail)
                ? '<button class="reminder-cell-btn r3" disabled title="Non disponible">R3</button>'
                : `<button class="reminder-cell-btn r3" data-action="send-reminder" data-id="${safeId}" data-type="3" title="Envoyer relance 3">R3</button>`;

        const r4Btn = r4Sent
            ? '<button class="reminder-cell-btn sent" disabled title="Envoyée">R4</button>'
            : (isPaid || !hasEmail)
                ? '<button class="reminder-cell-btn r4" disabled title="Non disponible">R4</button>'
                : `<button class="reminder-cell-btn r4" data-action="send-reminder" data-id="${safeId}" data-type="4" title="Coupure compte">R4</button>`;

        return `
            <tr data-history-id="${safeId}">
                <td><input type="checkbox" class="history-checkbox" data-id="${safeId}" ${isPaid ? 'disabled' : ''}></td>
                <td class="invoice-number-cell">${escapeHtml(inv.invoice_number)}</td>
                <td class="client-cell" title="${escapeHtml(inv.client_name)}">${escapeHtml(inv.client_name)}</td>
                <td class="amount-cell">${inv.total_ttc_formatted || formatCurrency(inv.total_ttc)}</td>
                <td>${paymentBadge}</td>
                <td>${r1Btn}</td>
                <td>${r2Btn}</td>
                <td>${r3Btn}</td>
                <td>${r4Btn}</td>
                <td class="actions-cell">
                    <button class="history-action-btn download" data-action="download" data-id="${safeId}" title="Télécharger">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                    </button>
                    <button class="history-action-btn delete" data-action="delete-history" data-id="${safeId}" title="Supprimer">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="3 6 5 6 21 6"></polyline>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                        </svg>
                    </button>
                </td>
            </tr>
        `;
    }).join('');

    // Attach event listeners
    tbody.querySelectorAll('[data-action="download"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = decodeURIComponent(btn.dataset.id);
            downloadFromHistory(id);
        });
    });

    tbody.querySelectorAll('[data-action="delete-history"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = decodeURIComponent(btn.dataset.id);
            deleteFromHistory(id);
        });
    });

    tbody.querySelectorAll('[data-action="toggle-payment"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = decodeURIComponent(btn.dataset.id);
            togglePaymentStatus(id);
        });
    });

    tbody.querySelectorAll('[data-action="send-reminder"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const id = decodeURIComponent(btn.dataset.id);
            const type = parseInt(btn.dataset.type);
            sendSingleReminder(id, type);
        });
    });

    // Attach checkbox change listeners for bulk actions
    tbody.querySelectorAll('.history-checkbox').forEach(cb => {
        cb.addEventListener('change', () => {
            updateBulkActionsBar();
        });
    });

    // Reset bulk actions bar
    updateBulkActionsBar();
}

function updateHistoryStats(history) {
    const statsContainer = document.getElementById('history-stats');
    if (!history || history.length === 0) {
        statsContainer.innerHTML = '';
        return;
    }

    const totalInvoices = history.length;
    const totalTTC = history.reduce((sum, inv) => sum + (inv.total_ttc || 0), 0);
    const paidCount = history.filter(inv => inv.payment_status === 'paid').length;
    const unpaidCount = totalInvoices - paidCount;
    const unpaidTotal = history.filter(inv => inv.payment_status !== 'paid').reduce((sum, inv) => sum + (inv.total_ttc || 0), 0);

    const r1Count = history.filter(inv => inv.reminder_1_sent).length;
    const r2Count = history.filter(inv => inv.reminder_2_sent).length;
    const r3Count = history.filter(inv => inv.reminder_3_sent).length;

    statsContainer.innerHTML = `
        <div class="stat-card">
            <div class="stat-value">${totalInvoices}</div>
            <div class="stat-label">Factures</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--color-warning)">${unpaidCount}</div>
            <div class="stat-label">Impayées (${formatCurrency(unpaidTotal)})</div>
        </div>
        <div class="stat-card">
            <div class="stat-value" style="color: var(--color-success)">${paidCount}</div>
            <div class="stat-label">Payées</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">${r1Count} / ${r2Count} / ${r3Count}</div>
            <div class="stat-label">Relances R1/R2/R3</div>
        </div>
    `;
}

function downloadFromHistory(id) {
    window.location.href = `/api/history/download/${encodeURIComponent(id)}`;
}

async function togglePaymentStatus(id) {
    const inv = historyData.find(h => h.id === id);
    if (!inv) return;

    const newStatus = inv.payment_status === 'paid' ? 'pending' : 'paid';
    const statusText = newStatus === 'paid' ? 'payée' : 'impayée';

    try {
        const response = await fetch(`/api/history/${encodeURIComponent(id)}/payment`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });

        if (response.ok) {
            showToast(`Facture marquée comme ${statusText}`, 'success');
            loadHistory();
        } else {
            showToast('Erreur lors de la mise à jour', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de la mise à jour', 'error');
    }
}

async function sendSingleReminder(id, reminderType) {
    const inv = historyData.find(h => h.id === id);
    if (!inv) return;

    const reminderNames = {
        1: '1ère relance (48h)',
        2: '2ème relance (avertissement)',
        3: '3ème relance (dernier avis)'
    };

    if (!confirm(`Envoyer ${reminderNames[reminderType]} pour la facture ${inv.invoice_number} à ${inv.client_email} ?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/history/${encodeURIComponent(id)}/reminder/${reminderType}`, {
            method: 'POST'
        });

        const data = await response.json();

        if (data.success) {
            showToast(`${reminderNames[reminderType]} envoyée avec succès`, 'success');
            loadHistory();
        } else {
            showToast(data.error || 'Erreur lors de l\'envoi', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de l\'envoi de la relance', 'error');
    }
}

async function sendAllReminders(reminderType) {
    const reminderNames = {
        1: '1ère relance',
        2: '2ème relance',
        3: '3ème relance'
    };

    // Get selected invoices or all unpaid invoices
    const selectedCheckboxes = document.querySelectorAll('.history-checkbox:checked');
    let invoiceIds = [];

    if (selectedCheckboxes.length > 0) {
        invoiceIds = Array.from(selectedCheckboxes).map(cb => decodeURIComponent(cb.dataset.id));
    }

    const reminderKey = `reminder_${reminderType}_sent`;
    const eligibleCount = invoiceIds.length > 0
        ? historyData.filter(inv => invoiceIds.includes(inv.id) && inv.payment_status !== 'paid' && inv.client_email && !inv[reminderKey]).length
        : historyData.filter(inv => inv.payment_status !== 'paid' && inv.client_email && !inv[reminderKey]).length;

    if (eligibleCount === 0) {
        showToast(`Aucune facture éligible pour la ${reminderNames[reminderType]}`, 'error');
        return;
    }

    const message = `Envoyer ${reminderNames[reminderType]} pour ${eligibleCount} facture(s) ?`;

    if (!confirm(message)) {
        return;
    }

    const btn = document.getElementById(`btn-send-all-reminder-${reminderType}`);
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = '...';

    try {
        const response = await fetch(`/api/history/reminders/send-all/${reminderType}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ invoice_ids: invoiceIds })
        });

        const data = await response.json();

        if (data.success) {
            showReminderResults(data.results);
            loadHistory();
        } else {
            showToast(data.error || 'Erreur lors de l\'envoi', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de l\'envoi des relances', 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

function showReminderResults(results) {
    document.getElementById('reminder-results-summary').innerHTML = `
        <div class="stat">
            <div class="stat-value success">${results.sent}</div>
            <div class="stat-label">Envoyées</div>
        </div>
        <div class="stat">
            <div class="stat-value warning">${results.skipped}</div>
            <div class="stat-label">Ignorées</div>
        </div>
        <div class="stat">
            <div class="stat-value error">${results.failed}</div>
            <div class="stat-label">Échouées</div>
        </div>
    `;

    document.getElementById('reminder-results-list').innerHTML = results.details.map(d => {
        let iconClass = 'success';
        let icon = '✓';
        if (d.status === 'failed') {
            iconClass = 'error';
            icon = '✗';
        } else if (d.status === 'skipped') {
            iconClass = 'skipped';
            icon = '–';
        }

        return `
            <div class="email-result-item">
                <div class="email-result-icon ${iconClass}">${icon}</div>
                <div class="email-result-info">
                    <div class="email-result-invoice">${d.invoice_number}</div>
                    <div class="email-result-message">${d.message}</div>
                </div>
            </div>
        `;
    }).join('');

    document.getElementById('reminder-results-modal').classList.remove('hidden');
}

async function deleteFromHistory(id) {
    const inv = historyData.find(h => h.id === id);
    const name = inv ? inv.invoice_number : id;

    if (!confirm(`Êtes-vous sûr de vouloir supprimer "${name}" de l'historique ?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/history/${encodeURIComponent(id)}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('Facture supprimée de l\'historique', 'success');
            loadHistory();
        } else {
            showToast('Erreur lors de la suppression', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de la suppression', 'error');
    }
}

// History search
const historySearchInput = document.getElementById('history-search');
let searchTimeout = null;

if (historySearchInput) {
    historySearchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            loadHistory(e.target.value);
        }, 300);
    });
}

// Refresh history button
const btnRefreshHistory = document.getElementById('btn-refresh-history');
if (btnRefreshHistory) {
    btnRefreshHistory.addEventListener('click', () => {
        const search = historySearchInput ? historySearchInput.value : '';
        loadHistory(search);
        showToast('Historique actualisé', 'success');
    });
}

// History filter
const historyFilterSelect = document.getElementById('history-filter');
if (historyFilterSelect) {
    historyFilterSelect.addEventListener('change', (e) => {
        historyFilter = e.target.value;
        applyHistoryFilter();
    });
}

// Send all reminders buttons (R1, R2, R3)
const btnSendAllR1 = document.getElementById('btn-send-all-reminder-1');
const btnSendAllR2 = document.getElementById('btn-send-all-reminder-2');
const btnSendAllR3 = document.getElementById('btn-send-all-reminder-3');

if (btnSendAllR1) btnSendAllR1.addEventListener('click', () => sendAllReminders(1));
if (btnSendAllR2) btnSendAllR2.addEventListener('click', () => sendAllReminders(2));
if (btnSendAllR3) btnSendAllR3.addEventListener('click', () => sendAllReminders(3));

// Select all history checkbox
const selectAllHistory = document.getElementById('select-all-history');
if (selectAllHistory) {
    selectAllHistory.addEventListener('change', (e) => {
        const checkboxes = document.querySelectorAll('.history-checkbox:not(:disabled)');
        checkboxes.forEach(cb => cb.checked = e.target.checked);
        updateBulkActionsBar();
    });
}

// ==========================================================================
// Bulk Actions Functions
// ==========================================================================

function getSelectedInvoiceIds() {
    const checkboxes = document.querySelectorAll('.history-checkbox:checked');
    return Array.from(checkboxes).map(cb => decodeURIComponent(cb.dataset.id));
}

function updateBulkActionsBar() {
    const selected = getSelectedInvoiceIds();
    const bar = document.getElementById('bulk-actions-bar');
    const countSpan = document.getElementById('bulk-selected-count');

    if (selected.length > 0) {
        bar.classList.remove('hidden');
        countSpan.textContent = selected.length;
    } else {
        bar.classList.add('hidden');
    }

    // Update select all checkbox state
    const allCheckboxes = document.querySelectorAll('.history-checkbox:not(:disabled)');
    const allChecked = allCheckboxes.length > 0 && Array.from(allCheckboxes).every(cb => cb.checked);
    const selectAll = document.getElementById('select-all-history');
    if (selectAll) {
        selectAll.checked = allChecked;
        selectAll.indeterminate = selected.length > 0 && !allChecked;
    }
}

// Bulk Info
document.getElementById('btn-bulk-info')?.addEventListener('click', async () => {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    try {
        const response = await fetch('/api/history/bulk-info', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids })
        });
        const data = await response.json();

        if (data.success) {
            showBulkInfoModal(data.invoices, data.summary);
        }
    } catch (error) {
        showToast('Erreur lors du chargement des informations', 'error');
    }
});

function showBulkInfoModal(invoices, summary) {
    const modal = document.getElementById('bulk-info-modal');
    const summaryDiv = document.getElementById('bulk-summary');
    const listDiv = document.getElementById('bulk-invoices-list');

    summaryDiv.innerHTML = `
        <div class="bulk-summary-item">
            <div class="bulk-summary-value">${summary.count}</div>
            <div class="bulk-summary-label">Factures</div>
        </div>
        <div class="bulk-summary-item">
            <div class="bulk-summary-value">${formatCurrency(summary.total_ht)}</div>
            <div class="bulk-summary-label">Total HT</div>
        </div>
        <div class="bulk-summary-item">
            <div class="bulk-summary-value">${formatCurrency(summary.total_tva)}</div>
            <div class="bulk-summary-label">TVA</div>
        </div>
        <div class="bulk-summary-item">
            <div class="bulk-summary-value">${formatCurrency(summary.total_ttc)}</div>
            <div class="bulk-summary-label">Total TTC</div>
        </div>
        <div class="bulk-summary-item">
            <div class="bulk-summary-value" style="color: var(--color-success)">${summary.paid_count}</div>
            <div class="bulk-summary-label">Payées</div>
        </div>
        <div class="bulk-summary-item">
            <div class="bulk-summary-value" style="color: var(--color-warning)">${summary.unpaid_count}</div>
            <div class="bulk-summary-label">Impayées</div>
        </div>
    `;

    listDiv.innerHTML = `
        <table>
            <thead>
                <tr>
                    <th>N° Facture</th>
                    <th>Client</th>
                    <th>Montant TTC</th>
                    <th>Statut</th>
                </tr>
            </thead>
            <tbody>
                ${invoices.map(inv => `
                    <tr>
                        <td>${escapeHtml(inv.invoice_number)}</td>
                        <td>${escapeHtml(inv.client_name || inv.shipper)}</td>
                        <td>${inv.total_ttc_formatted || formatCurrency(inv.total_ttc)}</td>
                        <td>
                            <span class="payment-badge ${inv.payment_status === 'paid' ? 'paid' : 'pending'}">
                                ${inv.payment_status === 'paid' ? 'Payée' : 'Impayée'}
                            </span>
                        </td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;

    modal.classList.remove('hidden');
}

// Bulk Info Modal close
document.getElementById('bulk-info-modal-close')?.addEventListener('click', () => {
    document.getElementById('bulk-info-modal').classList.add('hidden');
});
document.getElementById('btn-close-bulk-info')?.addEventListener('click', () => {
    document.getElementById('bulk-info-modal').classList.add('hidden');
});

// Bulk Download (ZIP)
document.getElementById('btn-bulk-download')?.addEventListener('click', async () => {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    try {
        showToast('Préparation du téléchargement...', 'info');

        const response = await fetch('/api/history/bulk-download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids })
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `factures_${new Date().toISOString().slice(0, 10)}.zip`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
            showToast(`${ids.length} facture(s) téléchargée(s)`, 'success');
        } else {
            showToast('Erreur lors du téléchargement', 'error');
        }
    } catch (error) {
        showToast('Erreur lors du téléchargement', 'error');
    }
});

// Bulk Mark as Paid
document.getElementById('btn-bulk-paid')?.addEventListener('click', async () => {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    if (!confirm(`Marquer ${ids.length} facture(s) comme payée(s) ?`)) return;

    try {
        const response = await fetch('/api/history/bulk-payment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids, status: 'paid' })
        });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
            loadHistory();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de la mise à jour', 'error');
    }
});

// Bulk Mark as Unpaid
document.getElementById('btn-bulk-unpaid')?.addEventListener('click', async () => {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    if (!confirm(`Marquer ${ids.length} facture(s) comme impayée(s) ?`)) return;

    try {
        const response = await fetch('/api/history/bulk-payment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids, status: 'pending' })
        });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
            loadHistory();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de la mise à jour', 'error');
    }
});

// Bulk Delete
document.getElementById('btn-bulk-delete')?.addEventListener('click', async () => {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    if (!confirm(`Supprimer définitivement ${ids.length} facture(s) de l'historique ?`)) return;

    try {
        const response = await fetch('/api/history/bulk-delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids })
        });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
            loadHistory();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de la suppression', 'error');
    }
});

// Bulk Send Reminders (R1, R2, R3, R4)
async function bulkSendReminder(reminderType) {
    const ids = getSelectedInvoiceIds();
    if (ids.length === 0) return;

    const reminderNames = { 1: 'Relance 1', 2: 'Relance 2', 3: 'Relance 3', 4: 'Relance 4 (Coupure)' };
    if (!confirm(`Envoyer ${reminderNames[reminderType]} à ${ids.length} facture(s) sélectionnée(s) ?`)) return;

    try {
        showToast('Envoi des relances en cours...', 'info');

        const response = await fetch('/api/history/bulk-reminder', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids, reminder_type: reminderType })
        });
        const data = await response.json();

        if (data.success) {
            showToast(data.message, 'success');
            loadHistory();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        showToast('Erreur lors de l\'envoi des relances', 'error');
    }
}

document.getElementById('btn-bulk-r1')?.addEventListener('click', () => bulkSendReminder(1));
document.getElementById('btn-bulk-r2')?.addEventListener('click', () => bulkSendReminder(2));
document.getElementById('btn-bulk-r3')?.addEventListener('click', () => bulkSendReminder(3));
document.getElementById('btn-bulk-r4')?.addEventListener('click', () => bulkSendReminder(4));

// Reminder results modal close
const reminderResultsModal = document.getElementById('reminder-results-modal');
if (reminderResultsModal) {
    document.getElementById('reminder-modal-close').addEventListener('click', () => {
        reminderResultsModal.classList.add('hidden');
    });
    document.getElementById('btn-close-reminder-results').addEventListener('click', () => {
        reminderResultsModal.classList.add('hidden');
    });
}

// ==========================================================================
// Email Preview
// ==========================================================================

const emailPreviewModal = document.getElementById('email-preview-modal');
if (emailPreviewModal) {
    document.getElementById('email-preview-close').addEventListener('click', () => {
        emailPreviewModal.classList.add('hidden');
    });
    document.getElementById('btn-close-email-preview').addEventListener('click', () => {
        emailPreviewModal.classList.add('hidden');
    });
    // Close on backdrop click
    emailPreviewModal.querySelector('.modal-backdrop').addEventListener('click', () => {
        emailPreviewModal.classList.add('hidden');
    });
}

/**
 * Affiche une prévisualisation de l'email
 * @param {string} emailType - 'invoice', 'reminder_1', 'reminder_2', 'reminder_3', 'reminder_4'
 */
async function previewEmail(emailType) {
    const modal = document.getElementById('email-preview-modal');
    const iframe = document.getElementById('email-preview-iframe');
    const title = document.getElementById('email-preview-title');

    const titles = {
        'invoice': 'Prévisualisation - Email de facture',
        'reminder_1': 'Prévisualisation - Relance 1 (48h)',
        'reminder_2': 'Prévisualisation - Relance 2 (Avertissement)',
        'reminder_3': 'Prévisualisation - Relance 3 (Dernier avis)',
        'reminder_4': 'Prévisualisation - Relance 4 (Coupure compte)'
    };

    title.textContent = titles[emailType] || 'Prévisualisation';

    try {
        // Charger le HTML dans l'iframe
        iframe.src = `/api/email/preview/${emailType}`;
        modal.classList.remove('hidden');
    } catch (error) {
        console.error('Error loading preview:', error);
        showToast('Erreur lors du chargement de la prévisualisation', 'error');
    }
}

// ==========================================================================
// Utilities
// ==========================================================================

function formatCurrency(amount) {
    return new Intl.NumberFormat('fr-FR', {
        style: 'currency',
        currency: 'EUR'
    }).format(amount);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}

// ==========================================================================
// User Management (Admin only)
// ==========================================================================

let usersData = [];

async function loadUsers() {
    if (!window.currentUser || !window.currentUser.isAdmin) return;

    try {
        const response = await fetch('/api/users');
        const data = await response.json();

        if (data.success) {
            usersData = data.users;
            renderUsers();
        }
    } catch (error) {
        console.error('Error loading users:', error);
        showToast('Erreur lors du chargement des utilisateurs', 'error');
    }
}

function renderUsers() {
    const usersList = document.getElementById('users-list');
    if (!usersList) return;

    if (usersData.length === 0) {
        usersList.innerHTML = '<tr><td colspan="4" class="empty-message">Aucun utilisateur</td></tr>';
        return;
    }

    const roleLabels = {
        'super_admin': 'Super Admin',
        'admin': 'Administrateur',
        'user': 'Utilisateur'
    };

    usersList.innerHTML = usersData.map(user => `
        <tr>
            <td>${escapeHtml(user.name) || '-'}</td>
            <td>${escapeHtml(user.email)}</td>
            <td><span class="role-badge ${user.role}">${roleLabels[user.role] || user.role}</span></td>
            <td>
                <div class="user-actions">
                    ${user.role !== 'super_admin' || window.currentUser.isSuperAdmin ? `
                        <button class="btn-edit-user" data-id="${user._id}">Modifier</button>
                        ${user._id !== window.currentUser.id && user.role !== 'super_admin' ? `
                            <button class="btn-delete-user" data-id="${user._id}">Supprimer</button>
                        ` : ''}
                    ` : ''}
                    ${window.currentUser.isSuperAdmin && user._id !== window.currentUser.id && !window.currentUser.isImpersonating ? `
                        <button class="btn-impersonate" data-id="${user._id}" data-name="${escapeHtml(user.name || user.email)}">
                            Accéder
                        </button>
                    ` : ''}
                </div>
            </td>
        </tr>
    `).join('');

    // Add event listeners
    usersList.querySelectorAll('.btn-edit-user').forEach(btn => {
        btn.addEventListener('click', () => editUser(btn.dataset.id));
    });

    usersList.querySelectorAll('.btn-delete-user').forEach(btn => {
        btn.addEventListener('click', () => deleteUser(btn.dataset.id));
    });

    // Impersonate buttons
    usersList.querySelectorAll('.btn-impersonate').forEach(btn => {
        btn.addEventListener('click', () => impersonateUser(btn.dataset.id, btn.dataset.name));
    });
}

function openUserModal(user = null) {
    const modal = document.getElementById('user-modal');
    const title = document.getElementById('user-modal-title');
    const passwordHint = document.getElementById('password-hint-user');
    const welcomeEmailGroup = document.getElementById('welcome-email-group');

    if (user) {
        title.textContent = 'Modifier l\'utilisateur';
        document.getElementById('user-id').value = user._id;
        document.getElementById('user-name').value = user.name || '';
        document.getElementById('user-email').value = user.email;
        document.getElementById('user-password').value = '';
        document.getElementById('user-role').value = user.role;
        passwordHint.style.display = 'block';
        document.getElementById('user-password').required = false;
        if (welcomeEmailGroup) welcomeEmailGroup.style.display = 'none';
    } else {
        title.textContent = 'Ajouter un utilisateur';
        document.getElementById('user-id').value = '';
        document.getElementById('user-name').value = '';
        document.getElementById('user-email').value = '';
        document.getElementById('user-password').value = '';
        document.getElementById('user-role').value = 'user';
        passwordHint.style.display = 'none';
        document.getElementById('user-password').required = true;
        if (welcomeEmailGroup) {
            welcomeEmailGroup.style.display = 'block';
            document.getElementById('user-send-welcome').checked = true;
        }
    }

    modal.classList.remove('hidden');
}

function closeUserModal() {
    const modal = document.getElementById('user-modal');
    if (modal) modal.classList.add('hidden');
}

function editUser(userId) {
    const user = usersData.find(u => u._id === userId);
    if (user) {
        openUserModal(user);
    }
}

async function saveUser() {
    console.log('saveUser called');

    const saveBtn = document.getElementById('btn-save-user');
    if (saveBtn) {
        saveBtn.disabled = true;
        saveBtn.textContent = 'Enregistrement...';
    }

    const userId = document.getElementById('user-id').value;
    const userData = {
        name: document.getElementById('user-name').value,
        email: document.getElementById('user-email').value,
        role: document.getElementById('user-role').value
    };

    const password = document.getElementById('user-password').value;
    if (password) {
        userData.password = password;
    }

    // Pour les nouveaux utilisateurs, inclure l'option d'email de bienvenue
    const sendWelcomeCheckbox = document.getElementById('user-send-welcome');
    if (!userId && sendWelcomeCheckbox) {
        userData.send_welcome_email = sendWelcomeCheckbox.checked;
    }

    console.log('User data:', userData);

    try {
        let response;
        if (userId) {
            // Update
            response = await fetch(`/api/users/${userId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        } else {
            // Create
            if (!password) {
                showToast('Le mot de passe est requis', 'error');
                if (saveBtn) {
                    saveBtn.disabled = false;
                    saveBtn.textContent = 'Enregistrer';
                }
                return;
            }
            console.log('Creating user...');
            response = await fetch('/api/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(userData)
            });
        }

        console.log('Response status:', response.status);
        const data = await response.json();
        console.log('Response data:', data);

        if (data.success || data.user) {
            let message = userId ? 'Utilisateur modifié' : 'Utilisateur créé';

            // Si c'est une création, vérifier si l'email de bienvenue a été envoyé
            if (!userId && data.welcome_email_sent !== undefined) {
                if (data.welcome_email_sent) {
                    message += ' - Email de bienvenue envoyé';
                } else {
                    showToast('Attention: Email de bienvenue non envoyé - ' + (data.welcome_email_error || 'Erreur'), 'warning');
                }
            }

            showToast(message, 'success');
            closeUserModal();
            loadUsers();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        console.error('Error saving user:', error);
        showToast('Erreur lors de l\'enregistrement: ' + error.message, 'error');
    } finally {
        if (saveBtn) {
            saveBtn.disabled = false;
            saveBtn.textContent = 'Enregistrer';
        }
    }
}

async function deleteUser(userId) {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) return;

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: 'DELETE'
        });

        const data = await response.json();

        if (data.success) {
            showToast('Utilisateur supprimé', 'success');
            loadUsers();
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        console.error('Error deleting user:', error);
        showToast('Erreur lors de la suppression', 'error');
    }
}

async function changeMyPassword(e) {
    e.preventDefault();

    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;

    try {
        const response = await fetch('/api/me/password', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: currentPassword, new_password: newPassword })
        });

        const data = await response.json();

        if (data.success) {
            showToast('Mot de passe modifié avec succès', 'success');
            document.getElementById('current-password').value = '';
            document.getElementById('new-password').value = '';
        } else {
            showToast(data.error || 'Erreur', 'error');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showToast('Erreur lors du changement de mot de passe', 'error');
    }
}

// User modal event listeners
const userModal = document.getElementById('user-modal');
if (userModal) {
    document.getElementById('user-modal-close')?.addEventListener('click', closeUserModal);
    document.getElementById('btn-cancel-user')?.addEventListener('click', closeUserModal);
    document.getElementById('btn-save-user')?.addEventListener('click', saveUser);
    document.getElementById('btn-add-user')?.addEventListener('click', () => openUserModal());

    userModal.querySelector('.modal-backdrop')?.addEventListener('click', closeUserModal);
}

// Change password form
const changePasswordForm = document.getElementById('change-password-form');
if (changePasswordForm) {
    changePasswordForm.addEventListener('submit', changeMyPassword);
}

// ==========================================================================
// Impersonation
// ==========================================================================

async function impersonateUser(userId, userName) {
    if (!confirm(`Voulez-vous accéder au compte de "${userName}" ?\n\nVous pourrez revenir à votre compte à tout moment.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/users/${userId}/impersonate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showToast(`Vous êtes maintenant connecté en tant que ${data.user.email}`, 'success');
            // Reload the page to update all user-related UI
            window.location.reload();
        } else {
            showToast(data.error || 'Erreur lors de l\'impersonation', 'error');
        }
    } catch (error) {
        console.error('Error impersonating user:', error);
        showToast('Erreur lors de l\'impersonation', 'error');
    }
}

async function stopImpersonation() {
    try {
        const response = await fetch('/api/stop-impersonate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });

        const data = await response.json();

        if (data.success) {
            showToast('Vous êtes de retour sur votre compte', 'success');
            // Reload the page to update all user-related UI
            window.location.reload();
        } else {
            showToast(data.error || 'Erreur lors du retour au compte', 'error');
        }
    } catch (error) {
        console.error('Error stopping impersonation:', error);
        showToast('Erreur lors du retour au compte', 'error');
    }
}

function initImpersonationBanner() {
    // Check if user is impersonating
    if (window.currentUser && window.currentUser.isImpersonating) {
        const banner = document.getElementById('impersonation-banner');
        const userName = document.getElementById('impersonated-user-name');
        const stopBtn = document.getElementById('btn-stop-impersonate');

        if (banner && userName) {
            userName.textContent = `${window.currentUser.name || window.currentUser.email}`;
            banner.classList.remove('hidden');
            document.body.classList.add('impersonating');

            if (stopBtn) {
                stopBtn.addEventListener('click', stopImpersonation);
            }
        }
    }
}

// ==========================================================================
// Init
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Initialize impersonation banner
    initImpersonationBanner();

    // Check URL hash for initial tab
    if (window.location.hash === '#clients') {
        document.querySelector('[data-tab="clients"]').click();
    } else if (window.location.hash === '#settings') {
        document.querySelector('[data-tab="settings"]').click();
    } else if (window.location.hash === '#history') {
        document.querySelector('[data-tab="history"]').click();
    } else if (window.location.hash === '#users') {
        const usersTab = document.querySelector('[data-tab="users"]');
        if (usersTab) usersTab.click();
    }
});
