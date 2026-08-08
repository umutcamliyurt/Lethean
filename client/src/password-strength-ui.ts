import { validatePasswordStrength } from './crypto.js';

const confirmInput = document.getElementById('password-confirm') as HTMLInputElement | null;
const strengthMeter = document.getElementById('password-strength') as HTMLElement | null;
const strengthHint = document.getElementById('password-strength-hint') as HTMLElement | null;

if (confirmInput && strengthMeter && strengthHint) {
  const segments = strengthMeter.querySelectorAll<HTMLElement>('.strength-segment');
  const TIERS = ['weak', 'weak', 'fair', 'good', 'strong'];

  let generation = 0;

  const update = async (): Promise<void> => {
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

export async function requireStrongPassword(password: string): Promise<{ valid: boolean; reason: string | null }> {
  const { valid, errors } = await validatePasswordStrength(password);
  return { valid, reason: errors[0] || null };
}
