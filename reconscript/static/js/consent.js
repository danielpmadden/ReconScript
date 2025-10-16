document.addEventListener('DOMContentLoaded', () => {
  const targetInput = document.getElementById('target');
  const evidenceSelect = document.getElementById('evidence_level');
  const consentFile = document.getElementById('consent_file');
  const consentCheckbox = document.getElementById('consent_confirm');
  const submitBtn = document.getElementById('submit-btn');
  const modal = document.getElementById('consent-modal');
  const modalClose = document.getElementById('consent-close');
  let modalAcknowledged = false;

  const isLocal = (value) => {
    const normalized = (value || '').trim().toLowerCase();
    return normalized === '' || normalized === '127.0.0.1' || normalized === 'localhost' || normalized === '::1';
  };

  const requiresConsent = () => {
    if (!targetInput) return false;
    if (isLocal(targetInput.value)) return false;
    return true;
  };

  const updateState = () => {
    if (!submitBtn) return;
    if (!requiresConsent()) {
      submitBtn.disabled = false;
      if (modal) modal.style.display = 'none';
      return;
    }
    const hasFile = consentFile && consentFile.files && consentFile.files.length > 0;
    const confirmed = consentCheckbox && consentCheckbox.checked;
    submitBtn.disabled = !(hasFile && confirmed);
    if (!modalAcknowledged && modal) {
      modal.style.display = 'flex';
    }
  };

  if (modalClose) {
    modalClose.addEventListener('click', () => {
      modalAcknowledged = true;
      if (modal) modal.style.display = 'none';
      updateState();
    });
  }

  [targetInput, evidenceSelect, consentFile, consentCheckbox].forEach((element) => {
    if (!element) return;
    const events = element === consentFile ? ['change'] : ['input', 'change'];
    events.forEach((event) => element.addEventListener(event, updateState));
  });

  updateState();
});
