const BACKEND_URL = ''; // Fully unified single service on Render

let socket;
let candlestickSeries;
let latestPrice = 1.0925;
let pendingVerificationEmail = '';

function showBanner(elementId, message, type = 'error') {
  const el = document.getElementById(elementId);
  if (!el) return;
  el.textContent = message;
  el.className = `status-banner ${type}`;
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 4000);
}

function switchAuthTab(tab) {
  const signinForm = document.getElementById('signinForm');
  const signupForm = document.getElementById('signupForm');
  const verifyForm = document.getElementById('verifyForm');
  const forgotForm = document.getElementById('forgotForm');
  const tabSignin = document.getElementById('tabSignin');
  const tabSignup = document.getElementById('tabSignup');

  if (signinForm)
    signinForm.style.display = tab === 'signin' ? 'block' : 'none';
  if (signupForm)
    signupForm.style.display = tab === 'signup' ? 'block' : 'none';
  if (verifyForm) verifyForm.style.display = 'none';
  if (forgotForm) forgotForm.style.display = 'none';

  if (tabSignin) tabSignin.classList.toggle('active', tab === 'signin');
  if (tabSignup) tabSignup.classList.toggle('active', tab === 'signup');
}

function showForgotPassword(e) {
  e.preventDefault();
  const signinForm = document.getElementById('signinForm');
  const signupForm = document.getElementById('signupForm');
  const forgotForm = document.getElementById('forgotForm');

  if (signinForm) signinForm.style.display = 'none';
  if (signupForm) signupForm.style.display = 'none';
  if (forgotForm) forgotForm.style.display = 'block';
}

function backToSignin() {
  switchAuthTab('signin');
}

function togglePassword(fieldId, iconEl) {
  const input = document.getElementById(fieldId);
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    if (iconEl) iconEl.textContent = '🔒';
  } else {
    input.type = 'password';
    if (iconEl) iconEl.textContent = '👁️';
  }
}

window.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch(`${BACKEND_URL}/api/auth/status`, {
      credentials: 'include',
    });
    const data = await res.json();
    if (data.authenticated) showDashboard(data.user);
  } catch (err) {
    console.error('Session check failed:', err);
  }
});

const signinFormEl = document.getElementById('signinForm');
if (signinFormEl) {
  signinFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('signinEmail').value;
    const password = document.getElementById('signinPassword').value;
    const remember = document.getElementById('signinRemember').checked;

    const res = await fetch(`${BACKEND_URL}/api/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password, remember }),
    });
    const data = await res.json();
    if (data.success) {
      showBanner('signinStatus', data.message, 'success');
      setTimeout(() => showDashboard(data.user), 1000);
    } else {
      showBanner('signinStatus', data.error, 'error');
    }
  });
}

const signupFormEl = document.getElementById('signupForm');
if (signupFormEl) {
  signupFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('signupEmail').value;
    const password = document.getElementById('signupPassword').value;
    const phone = document.getElementById('signupPhone').value;

    const res = await fetch(`${BACKEND_URL}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password, phone }),
    });
    const data = await res.json();
    if (data.success && data.requiresVerification) {
      pendingVerificationEmail = data.email;
      signupFormEl.style.display = 'none';
      const verifyForm = document.getElementById('verifyForm');
      if (verifyForm) verifyForm.style.display = 'block';
      showBanner('verifyStatus', data.message, 'success');
    } else {
      showBanner('signupStatus', data.error, 'error');
    }
  });
}

const verifyFormEl = document.getElementById('verifyForm');
if (verifyFormEl) {
  verifyFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const code = document.getElementById('verificationCode').value;
    const res = await fetch(`${BACKEND_URL}/api/auth/verify-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        email: pendingVerificationEmail,
        code,
        remember: true,
      }),
    });
    const data = await res.json();
    if (data.success) {
      showBanner('verifyStatus', data.message, 'success');
      setTimeout(() => showDashboard(data.user), 1000);
    } else {
      showBanner('verifyStatus', data.error, 'error');
    }
  });
}

const forgotFormEl = document.getElementById('forgotForm');
if (forgotFormEl) {
  forgotFormEl.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('forgotEmail').value;
    const res = await fetch(`${BACKEND_URL}/api/auth/forgot-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    showBanner(
      'forgotStatus',
      data.message || data.error,
      data.success ? 'success' : 'error'
    );
  });
}

const btnLogoutEl = document.getElementById('btnLogout');
if (btnLogoutEl) {
  btnLogoutEl.addEventListener('click', async () => {
    if (socket) socket.disconnect();
    await fetch(`${BACKEND_URL}/api/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    });
    const dashContainer = document.getElementById('dashboardContainer');
    const authContainer = document.getElementById('authContainer');
    if (dashContainer) dashContainer.style.display = 'none';
    if (authContainer) authContainer.style.display = 'flex';
  });
}

async function showDashboard(user) {
  const authContainer = document.getElementById('authContainer');
  const dashContainer = document.getElementById('dashboardContainer');
  const userBalance = document.getElementById('userBalance');

  if (authContainer) authContainer.style.display = 'none';
  if (dashContainer) dashContainer.style.display = 'flex';
  if (userBalance)
    userBalance.textContent = `$${Number(user.balance).toFixed(2)}`;

  const chartContainer = document.getElementById('chartContainer');
  if (!chartContainer) return;
  chartContainer.innerHTML = '';

  const chart = LightweightCharts.createChart(chartContainer, {
    layout: { background: { color: '#0b0f19' }, textColor: '#8f9bb3' },
    grid: { vertLines: { color: '#161c2d' }, horzLines: { color: '#161c2d' } },
    timeScale: { borderColor: '#222b45' },
    rightPriceScale: { borderColor: '#222b45' },
  });

  candlestickSeries = chart.addCandlestickSeries({
    upColor: '#0faf59',
    downColor: '#ff4646',
    borderVisible: false,
    wickUpColor: '#0faf59',
    wickDownColor: '#ff4646',
  });

  const nowSec = Math.floor(Date.now() / 1000);
  let currentCandleTime = nowSec - (nowSec % 60);
  candlestickSeries.setData([
    {
      time: currentCandleTime - 120,
      open: 1.085,
      high: 1.09,
      low: 1.084,
      close: 1.0875,
    },
    {
      time: currentCandleTime - 60,
      open: 1.0875,
      high: 1.092,
      low: 1.086,
      close: 1.0905,
    },
    {
      time: currentCandleTime,
      open: 1.0905,
      high: 1.0935,
      low: 1.0895,
      close: 1.0925,
    },
  ]);

  let activeCandle = {
    time: currentCandleTime,
    open: 1.0905,
    high: 1.0935,
    low: 1.0895,
    close: 1.0925,
  };

  socket = io({ withCredentials: true });
  socket.on('priceTick', (data) => {
    latestPrice = data.price;
    const tickTime = Math.floor(data.time / 1000);
    const candleTimeWindow = tickTime - (tickTime % 60);

    if (candleTimeWindow > activeCandle.time) {
      activeCandle = {
        time: candleTimeWindow,
        open: latestPrice,
        high: latestPrice,
        low: latestPrice,
        close: latestPrice,
      };
    } else {
      activeCandle.high = Math.max(activeCandle.high, latestPrice);
      activeCandle.low = Math.min(activeCandle.low, latestPrice);
      activeCandle.close = latestPrice;
    }
    candlestickSeries.update(activeCandle);
  });
}

const btnHigher = document.getElementById('btnHigher');
const btnLower = document.getElementById('btnLower');

if (btnHigher)
  btnHigher.addEventListener('click', () => executeTrade('higher'));
if (btnLower) btnLower.addEventListener('click', () => executeTrade('lower'));

async function executeTrade(direction) {
  const amountInput = document.getElementById('tradeAmount');
  const assetSelect = document.getElementById('assetSelect');
  const userBalance = document.getElementById('userBalance');

  const amount = parseFloat(amountInput ? amountInput.value : 10) || 10;
  const asset = assetSelect ? assetSelect.value : 'EURUSD';

  const res = await fetch(`${BACKEND_URL}/api/trade/place`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ asset, amount, direction, entryPrice: latestPrice }),
  });
  const data = await res.json();
  if (data.success) {
    if (userBalance)
      userBalance.textContent = `$${Number(data.newBalance).toFixed(2)}`;
    showBanner(
      'tradeStatus',
      `Trade placed (${direction.toUpperCase()})!`,
      'success'
    );
  } else {
    showBanner('tradeStatus', data.error, 'error');
  }
}

// Modals
const depositModal = document.getElementById('depositModal');
const openDepositModal = document.getElementById('openDepositModal');
const closeModal = document.getElementById('closeModal');
const depositForm = document.getElementById('depositForm');

if (openDepositModal && depositModal) {
  openDepositModal.addEventListener(
    'click',
    () => (depositModal.style.display = 'flex')
  );
}
if (closeModal && depositModal) {
  closeModal.addEventListener(
    'click',
    () => (depositModal.style.display = 'none')
  );
}
if (depositForm) {
  depositForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch(`${BACKEND_URL}/api/deposit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        amount: document.getElementById('depositAmount').value,
        phone: document.getElementById('depositPhone').value,
      }),
    });
    const data = await res.json();
    showBanner(
      'depositStatus',
      data.message || data.error,
      data.success ? 'success' : 'error'
    );
  });
}

const withdrawModal = document.getElementById('withdrawModal');
const openWithdrawModal = document.getElementById('openWithdrawModal');
const closeWithdrawModal = document.getElementById('closeWithdrawModal');
const withdrawForm = document.getElementById('withdrawForm');

if (openWithdrawModal && withdrawModal) {
  openWithdrawModal.addEventListener(
    'click',
    () => (withdrawModal.style.display = 'flex')
  );
}
if (closeWithdrawModal && withdrawModal) {
  closeWithdrawModal.addEventListener(
    'click',
    () => (withdrawModal.style.display = 'none')
  );
}
if (withdrawForm) {
  withdrawForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = await fetch(`${BACKEND_URL}/api/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        amount: document.getElementById('withdrawAmount').value,
        phone: document.getElementById('withdrawPhone').value,
      }),
    });
    const data = await res.json();
    const userBalance = document.getElementById('userBalance');
    if (data.success) {
      if (userBalance)
        userBalance.textContent = `$${Number(data.newBalance).toFixed(2)}`;
      showBanner('withdrawStatus', data.message, 'success');
    } else {
      showBanner('withdrawStatus', data.error, 'error');
    }
  });
}

const historyModal = document.getElementById('historyModal');
const openHistoryModal = document.getElementById('openHistoryModal');
const closeHistoryModal = document.getElementById('closeHistoryModal');

if (openHistoryModal && historyModal) {
  openHistoryModal.addEventListener('click', async () => {
    historyModal.style.display = 'flex';
    const tbody = document.getElementById('historyTableBody');
    if (!tbody) return;
    tbody.innerHTML = '<tr><td colspan="7">Loading...</td></tr>';
    const res = await fetch(`${BACKEND_URL}/api/trade/history`, {
      credentials: 'include',
    });
    const data = await res.json();
    if (data.success && data.trades.length > 0) {
      tbody.innerHTML = data.trades
        .map(
          (t) => `
      <tr>
        <td>${t.asset}</td><td>${t.direction.toUpperCase()}</td><td>$${Number(t.amount).toFixed(2)}</td>
        <td>${t.entry_price}</td><td>${t.exit_price || 'Active...'}</td>
        <td class="${t.status}">${t.status.toUpperCase()}</td><td>$${Number(t.payout || 0).toFixed(2)}</td>
      </tr>
    `
        )
        .join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="7">No history found.</td></tr>';
    }
  });
}
if (closeHistoryModal && historyModal) {
  closeHistoryModal.addEventListener(
    'click',
    () => (historyModal.style.display = 'none')
  );
}

const tradeAmountInput = document.getElementById('tradeAmount');
if (tradeAmountInput) {
  tradeAmountInput.addEventListener('input', (e) => {
    const val = parseFloat(e.target.value) || 0;
    const profitEl = document.getElementById('potentialProfit');
    if (profitEl) {
      profitEl.textContent = `$${(val * 1.92).toFixed(2)}`;
    }
  });
}
