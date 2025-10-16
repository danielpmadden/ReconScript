/* eslint-disable no-console -- Logging to the console helps demo live progress. */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('scan-form');
  const status = document.getElementById('scan-status');
  const progressBar = document.getElementById('progress-bar');
  const progressMessage = document.getElementById('progress-message');
  const progressLog = document.getElementById('progress-log');
  const reportActions = document.getElementById('report-actions');
  const reportLink = document.getElementById('open-report');
  const reportFormat = document.getElementById('report-format');
  const summaryCard = document.getElementById('summary-card');
  const summaryList = document.getElementById('summary-list');
  const summaryNote = document.getElementById('summary-note');
  const summaryDuration = document.getElementById('summary-duration');
  const quickTest = document.getElementById('quick-test');
  const themeToggle = document.getElementById('theme-toggle');
  const aboutPanel = document.getElementById('about');
  const aboutTriggers = document.querySelectorAll('.about-trigger');
  const closeAbout = document.querySelector('.close-about');

  const THEME_KEY = 'reconscript-theme';
  const storedTheme = localStorage.getItem(THEME_KEY);
  if (storedTheme) {
    document.body.setAttribute('data-theme', storedTheme);
  }

  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const current = document.body.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      document.body.setAttribute('data-theme', current);
      localStorage.setItem(THEME_KEY, current);
    });
  }

  aboutTriggers.forEach((trigger) => {
    trigger.addEventListener('click', (event) => {
      event.preventDefault();
      aboutPanel.hidden = false;
      aboutPanel.classList.add('open');
    });
  });

  if (closeAbout) {
    closeAbout.addEventListener('click', () => {
      aboutPanel.classList.remove('open');
      aboutPanel.hidden = true;
    });
  }

  if (aboutPanel) {
    aboutPanel.addEventListener('click', (event) => {
      if (event.target === aboutPanel) {
        aboutPanel.hidden = true;
      }
    });
  }

  const appendLog = (text, level = 'info') => {
    const entry = document.createElement('div');
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
    entry.className = level === 'error' ? 'text-rose-300' : 'text-slate-300';
    progressLog.append(entry);
    progressLog.scrollTo({ top: progressLog.scrollHeight, behavior: 'smooth' });
  };

  const resetProgress = () => {
    progressBar.style.width = '0%';
    progressMessage.textContent = 'Waiting for scan…';
    progressLog.innerHTML = '';
    reportActions.classList.add('hidden');
    status.textContent = '';
    if (summaryCard) {
      summaryCard.classList.add('hidden');
    }
    if (summaryList) {
      summaryList.innerHTML = '';
    }
    if (summaryDuration) {
      summaryDuration.textContent = '';
    }
    if (summaryNote) {
      summaryNote.textContent = '';
      summaryNote.classList.add('hidden');
    }
  };

  const startStream = (jobId) => {
    const source = new EventSource(`/stream/${jobId}`);

    source.onmessage = (event) => {
      const payload = JSON.parse(event.data);
      if (payload.type === 'status') {
        progressMessage.textContent = `${payload.icon} ${payload.message}`;
        progressBar.style.width = `${Math.round(payload.progress * 100)}%`;
      }
      if (payload.type === 'log') {
        appendLog(payload.message, payload.level);
      }
      if (payload.type === 'complete') {
        progressMessage.textContent = `✅ ${payload.message}`;
        progressBar.style.width = '100%';
        reportActions.classList.remove('hidden');
        reportLink.href = payload.report_url;
        reportFormat.textContent = payload.format.toUpperCase();
        status.textContent = 'Report ready! Opening in a new tab…';
        if (summaryCard && summaryList) {
          summaryList.innerHTML = '';
          if (Array.isArray(payload.summary)) {
            payload.summary.forEach((item) => {
              if (!item || !item.label) return;
              const dt = document.createElement('dt');
              dt.textContent = item.label;
              dt.className = 'font-semibold text-slate-300';
              const dd = document.createElement('dd');
              dd.textContent = item.value;
              dd.className = 'text-slate-200';
              summaryList.append(dt, dd);
            });
          }
          if (summaryDuration) {
            summaryDuration.textContent = payload.duration ? `Duration ${payload.duration}` : '';
          }
          if (summaryNote) {
            const openPorts = Array.isArray(payload.open_ports) ? payload.open_ports.length : 0;
            if (openPorts === 0) {
              summaryNote.textContent = 'No open ports detected — review findings for additional context.';
              summaryNote.classList.remove('hidden');
            } else {
              summaryNote.textContent = '';
              summaryNote.classList.add('hidden');
            }
          }
          summaryCard.classList.remove('hidden');
        }
        try {
          window.open(payload.report_url, '_blank');
        } catch (error) {
          console.warn('Automatic report open blocked by the browser.', error);
        }
        source.close();
      }
      if (payload.type === 'error') {
        progressMessage.textContent = `❌ ${payload.message}`;
        status.textContent = 'Scan failed. Check the log for details.';
        if (summaryCard) {
          summaryCard.classList.add('hidden');
        }
        source.close();
      }
    };

    source.onerror = () => {
      source.close();
    };
  };

  const submitScan = async (payload) => {
    try {
      status.textContent = 'Starting scan…';
      // Post JSON payload so the Flask backend can start the scan asynchronously.
      const response = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || 'Failed to start scan');
      }
      appendLog('Scan launched. Listening for updates…');
      startStream(data.job_id);
    } catch (error) {
      status.textContent = error.message;
      appendLog(error.message, 'error');
    }
  };

  if (form) {
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      resetProgress();
      // FormData captures the operator inputs so they can be sent as JSON.
      const formData = new FormData(form);
      const payload = Object.fromEntries(formData.entries());
      submitScan(payload);
    });
  }

  if (quickTest) {
    quickTest.addEventListener('click', () => {
      resetProgress();
      const payload = {
        target: '127.0.0.1',
        hostname: 'localhost',
        ports: '3000,443',
        format: 'html',
      };
      submitScan(payload);
    });
  }
});
