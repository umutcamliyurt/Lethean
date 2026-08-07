import { validatePasswordStrength } from './crypto.js';

const confirmInput = document.getElementById('password-confirm');
const strengthMeter = document.getElementById('password-strength');
const strengthHint = document.getElementById('password-strength-hint');

if (confirmInput && strengthMeter && strengthHint) {
  const segments = strengthMeter.querySelectorAll('.strength-segment');
  const TIERS = ['weak', 'weak', 'fair', 'good', 'strong'];

  let generation = 0;

  const update = async () => {
    const value = confirmInput.value;
    const myGeneration = ++generation;

    if (!value) {
      strengthMeter.dataset.tier = '';
      segments.forEach((seg) => seg.classList.remove('on'));
      strengthHint.textContent = 'Use 12+ characters, ideally a random password of several unrelated words.';
      strengthHint.classList.remove('error');
      return;
    }

    const { valid, score, errors } = await validatePasswordStrength(value);
    if (myGeneration !== generation) return;

    strengthMeter.dataset.tier = TIERS[score];
    segments.forEach((seg, i) => seg.classList.toggle('on', i < score));
    strengthHint.textContent = errors[0] || 'Looks good.';
    strengthHint.classList.toggle('error', !valid);
  };

  confirmInput.addEventListener('input', update);
  update();
}

export async function requireStrongPassword(password) {
  const { valid, errors } = await validatePasswordStrength(password);
  return { valid, reason: errors[0] || null };
}
