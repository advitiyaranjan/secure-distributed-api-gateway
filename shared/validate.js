// Minimal schema validation for request bodies. Unknown fields are rejected
// (mass-assignment protection) and every field has explicit bounds.
import { HttpError } from './http.js';

/**
 * schema: { field: { type: 'string'|'integer'|'array'|'object', required, min, max, pattern, enum, items } }
 * For strings min/max bound the length; for integers the value; for arrays the item count.
 */
export function validate(schema, input, { partial = false, path = '' } = {}) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, `${path || 'Body'} must be a JSON object`, { code: 'validation_error' });
  }
  const errors = [];
  const out = {};
  for (const key of Object.keys(input)) {
    if (!Object.hasOwn(schema, key)) errors.push(`${path}${key}: unknown field`);
  }
  for (const [key, rule] of Object.entries(schema)) {
    const value = input[key];
    const name = `${path}${key}`;
    if (value === undefined || value === null) {
      if (rule.required && !partial) errors.push(`${name}: is required`);
      continue;
    }
    const err = checkValue(rule, value, name);
    if (err) errors.push(...[err].flat());
    else out[key] = rule.type === 'string' && rule.trim !== false ? value.trim() : value;
  }
  if (errors.length) throw new HttpError(400, 'Validation failed', { code: 'validation_error', details: errors });
  return out;
}

function checkValue(rule, value, name) {
  switch (rule.type) {
    case 'string': {
      if (typeof value !== 'string') return `${name}: must be a string`;
      const v = rule.trim === false ? value : value.trim();
      if (rule.min !== undefined && v.length < rule.min) return `${name}: must be at least ${rule.min} characters`;
      if (rule.max !== undefined && v.length > rule.max) return `${name}: must be at most ${rule.max} characters`;
      if (rule.pattern && !rule.pattern.test(v)) return `${name}: has an invalid format`;
      if (rule.enum && !rule.enum.includes(v)) return `${name}: must be one of ${rule.enum.join(', ')}`;
      return null;
    }
    case 'integer':
      if (!Number.isSafeInteger(value)) return `${name}: must be an integer`;
      if (rule.min !== undefined && value < rule.min) return `${name}: must be >= ${rule.min}`;
      if (rule.max !== undefined && value > rule.max) return `${name}: must be <= ${rule.max}`;
      return null;
    case 'array': {
      if (!Array.isArray(value)) return `${name}: must be an array`;
      if (rule.min !== undefined && value.length < rule.min) return `${name}: needs at least ${rule.min} item(s)`;
      if (rule.max !== undefined && value.length > rule.max) return `${name}: allows at most ${rule.max} items`;
      if (!rule.items) return null;
      const errs = [];
      value.forEach((item, i) => {
        if (rule.items.type === 'object') {
          try {
            validate(rule.items.schema, item, { path: `${name}[${i}].` });
          } catch (e) {
            errs.push(...(e.details ?? [e.message]));
          }
        } else {
          const e = checkValue(rule.items, item, `${name}[${i}]`);
          if (e) errs.push(e);
        }
      });
      return errs.length ? errs : null;
    }
    default:
      return `${name}: unsupported rule`;
  }
}

/** Parses a non-negative integer query/path parameter with bounds. */
export function intParam(value, { name, min = 0, max = Number.MAX_SAFE_INTEGER, fallback } = {}) {
  if (value === undefined || value === '') {
    if (fallback !== undefined) return fallback;
    throw new HttpError(400, `${name} is required`, { code: 'validation_error' });
  }
  if (!/^\d{1,15}$/.test(String(value))) throw new HttpError(400, `${name} must be an integer`, { code: 'validation_error' });
  const n = Number(value);
  if (n < min || n > max) throw new HttpError(400, `${name} must be between ${min} and ${max}`, { code: 'validation_error' });
  return n;
}
