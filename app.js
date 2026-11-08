// Automatically use Render backend when hosted on GitHub Pages, or localhost for local testing
const BACKEND_URL = window.location.hostname.includes('github.io')
  ? 'https://tradenova-backend.onrender.com' // Replace with your exact Render service URL if different
  : '';

let socket;
let candlestickSeries;
let latestPrice = 1.0925;
let pendingVerificationEmail = '';

function showBanner(elementId, message, type = 'error') {
  const el = document.getElementById(elementId);
  el.textContent = message;
  el.className = `status-banner ${type}`;
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 4000);
}

function switchAuthTab(tab) {
  document.getElementById('signinForm').style.display =
    tab === 'signin' ? 'block' : 'none';
  document.getElementById('signupForm').style.display =
    tab === 'signup' ? 'block' : 'none';
  document.getElementById('verifyForm').style.display = 'none';
  document.getElementById('forgotForm').style.display = 'none';
  document
    .getElementById('tabSignin')
    .classList.toggle('active', tab === 'signin');
  document
    .getElementById('tabSignup')
    .classList.toggle('active', tab === 'signup');
}

function showForgotPassword(e) {
  e.preventDefault();
  document.getElementById('signinForm').style.display = 'none';
  document.getElementById('signupForm').style.display = 'none';
  document.getElementById('forgotForm').style.display = 'block';
}

function backToSignin() {
  switchAuthTab('signin');
}

window.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch(`${BACKEND_URL}/api/auth/status`, {
      credentials: 'include',
    });
    const data = await res.json();
    if (data.authenticated) {
      showDashboard(data.user);
    }
  } catch (err) {
    console.error('Session check failed:', err);
  }
});

// Sign In
document.getElementById('signinForm').addEventListener('submit', async (e) => {
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

// Sign Up (Triggers Verification Code Email)
document.getElementById('signupForm').addEventListener('submit', async (e) => {
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
    document.getElementById('signupForm').style.display = 'none';
    document.getElementById('verifyForm').style.display = 'block';
    showBanner('verifyStatus', data.message, 'success');
  } else {
    showBanner('signupStatus', data.error, 'error');
  }
});

// Verify Code Form
document.getElementById('verifyForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const code = document.getElementById('verificationCode').value;
  const remember = document.getElementById('signupRemember').checked;

  const res = await fetch(`${BACKEND_URL}/api/auth/verify-code`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email: pendingVerificationEmail, code, remember }),
  });
  const data = await res.json();

  if (data.success) {
    showBanner('verifyStatus', data.message, 'success');
    setTimeout(() => showDashboard(data.user), 1000);
  } else {
    showBanner('verifyStatus', data.error, 'error');
  }
});

document.getElementById('forgotForm').addEventListener('submit', async (e) => {
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

document.getElementById('btnLogout').addEventListener('click', async () => {
  if (socket) socket.disconnect();
  await fetch(`${BACKEND_URL}/api/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  });
  document.getElementById('dashboardContainer').style.display = 'none';
  document.getElementById('authContainer').style.display = 'flex';
});

// Dashboard & Live Charts
async function showDashboard(user) {
  document.getElementById('authContainer').style.display = 'none';
  document.getElementById('dashboardContainer').style.display = 'flex';
  document.getElementById('userBalance').textContent =
    `$${Number(user.balance).toFixed(2)}`;

  const chartContainer = document.getElementById('chartContainer');
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

  // Connect Socket.io with credentials support
  socket = io(BACKEND_URL || undefined, { withCredentials: true });
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

  window.addEventListener('resize', () => {
    chart.applyOptions({
      width: chartContainer.clientWidth,
      height: chartContainer.clientHeight,
    });
  });
}

// Place Trade
document
  .getElementById('btnHigher')
  .addEventListener('click', () => executeTrade('higher'));
document
  .getElementById('btnLower')
  .addEventListener('click', () => executeTrade('lower'));

async function executeTrade(direction) {
  const amount = parseFloat(document.getElementById('tradeAmount').value) || 10;
  const asset = document.getElementById('assetSelect').value;

  const res = await fetch(`${BACKEND_URL}/api/trade/place`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ asset, amount, direction, entryPrice: latestPrice }),
  });
  const data = await res.json();

  if (data.success) {
    document.getElementById('userBalance').textContent =
      `$${Number(data.newBalance).toFixed(2)}`;
    showBanner(
      'tradeStatus',
      `Trade placed (${direction.toUpperCase()}) at ${latestPrice}!`,
      'success'
    );
  } else {
    showBanner('tradeStatus', data.error, 'error');
  }
}

// Modals Setup
const depositModal = document.getElementById('depositModal');
document
  .getElementById('openDepositModal')
  .addEventListener('click', () => (depositModal.style.display = 'flex'));
document
  .getElementById('closeModal')
  .addEventListener('click', () => (depositModal.style.display = 'none'));

document.getElementById('depositForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const phone = document.getElementById('depositPhone').value;
  const amount = document.getElementById('depositAmount').value;

  const res = await fetch(`${BACKEND_URL}/api/deposit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ amount, phone }),
  });
  const data = await res.json();
  showBanner(
    'depositStatus',
    data.message || data.error,
    data.success ? 'success' : 'error'
  );
});

// Withdraw Modal
const withdrawModal = document.getElementById('withdrawModal');
document
  .getElementById('openWithdrawModal')
  .addEventListener('click', () => (withdrawModal.style.display = 'flex'));
document
  .getElementById('closeWithdrawModal')
  .addEventListener('click', () => (withdrawModal.style.display = 'none'));

document
  .getElementById('withdrawForm')
  .addEventListener('submit', async (e) => {
    e.preventDefault();
    const phone = document.getElementById('withdrawPhone').value;
    const amount = document.getElementById('withdrawAmount').value;

    const res = await fetch(`${BACKEND_URL}/api/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ amount, phone }),
    });
    const data = await res.json();

    if (data.success) {
      document.getElementById('userBalance').textContent =
        `$${Number(data.newBalance).toFixed(2)}`;
      showBanner('withdrawStatus', data.message, 'success');
    } else {
      showBanner('withdrawStatus', data.error, 'error');
    }
  });

// History Modal
const historyModal = document.getElementById('historyModal');
document
  .getElementById('openHistoryModal')
  .addEventListener('click', async () => {
    historyModal.style.display = 'flex';
    const tbody = document.getElementById('historyTableBody');
    tbody.innerHTML = '<tr><td colspan="7">Loading history...</td></tr>';

    const res = await fetch(`${BACKEND_URL}/api/trade/history`, {
      credentials: 'include',
    });
    const data = await res.json();
    if (data.success && data.trades.length > 0) {
      tbody.innerHTML = data.trades
        .map(
          (t) => `
      <tr>
        <td>${t.asset}</td>
        <td>${t.direction.toUpperCase()}</td>
        <td>$${Number(t.amount).toFixed(2)}</td>
        <td>${t.entry_price}</td>
        <td>${t.exit_price || 'Active...'}</td>
        <td class="${t.status}">${t.status.toUpperCase()}</td>
        <td>$${Number(t.payout || 0).toFixed(2)}</td>
      </tr>
    `
        )
        .join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="7">No past trades found.</td></tr>';
    }
  });
document
  .getElementById('closeHistoryModal')
  .addEventListener('click', () => (historyModal.style.display = 'none'));

document.getElementById('tradeAmount').addEventListener('input', (e) => {
  const val = parseFloat(e.target.value) || 0;
  document.getElementById('potentialProfit').textContent =
    `$${(val + val * 0.92).toFixed(2)}`;
});
