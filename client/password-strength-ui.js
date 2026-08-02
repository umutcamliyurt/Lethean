import { validatePasswordStrength } from './crypto.js';

const confirmInput = document.getElementById('password-confirm');
const strengthMeter = document.getElementById('password-strength');
const strengthHint = document.getElementById('password-strength-hint');

if (confirmInput && strengthMeter && strengthHint) {
  const segments = strengthMeter.querySelectorAll('.strength-segment');
  const TIERS = ['weak', 'weak', 'fair', 'good', 'strong'];

  const update = () => {
    const value = confirmInput.value;
    if (!value) {
      strengthMeter.dataset.tier = '';
      segments.forEach((seg) => seg.classList.remove('on'));
      strengthHint.textContent = 'Use 12+ characters, ideally a random passphrase of several unrelated words.';
      strengthHint.classList.remove('error');
      return;
    }
    const { valid, score, errors } = validatePasswordStrength(value);
    strengthMeter.dataset.tier = TIERS[score];
    segments.forEach((seg, i) => seg.classList.toggle('on', i < score));
    strengthHint.textContent = errors[0] || 'Looks good.';
    strengthHint.classList.toggle('error', !valid);
  };

  confirmInput.addEventListener('input', update);
  update();
}

export function requireStrongPassword(password) {
  const { valid, errors } = validatePasswordStrength(password);
  return { valid, reason: errors[0] || null };
}