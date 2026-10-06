import crypto from 'crypto';

type StudentRecord = Record<string, unknown>;

const HASH_PREFIX = 'scrypt$';

function hashPassword(plain: string): string {
  const salt = crypto.randomBytes(32);
  const derivedKey = crypto.scryptSync(plain, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('hex')}$${derivedKey.toString('hex')}`;
}

function maskDigits(value: string): string {
  if (value.length <= 4) {
    return 'xxx';
  }
  return `${'x'.repeat(value.length - 4)}${value.slice(-4)}`;
}

function maskRecord(record: StudentRecord): void {
  if (typeof record.name === 'string' && record.name.length > 1) {
    record.name = `${record.name.charAt(0)}${'x'.repeat(Math.max(record.name.length - 1, 2))}`;
  }

  if (typeof record.mobile === 'string') {
    record.mobile = maskDigits(record.mobile);
  }

  if (typeof record.cardid === 'string') {
    record.cardid = maskDigits(record.cardid);
  }

  if ('password' in record) {
    record.password = 'xxx';
  }
}

function hashData(data: unknown): void {
  if (!data || typeof data !== 'object') {
    return;
  }

  const d = data as StudentRecord;
  if (
    typeof d.password === 'string' &&
    d.password.length > 0 &&
    !d.password.startsWith(HASH_PREFIX) &&
    d.password !== 'xxx'
  ) {
    d.password = hashPassword(d.password);
  }
}

function isInternalDocumentQuery(params: unknown): boolean {
  if (!params || typeof params !== 'object') {
    return false;
  }
  const where = (params as StudentRecord).where;
  return !!where && typeof where === 'object' && 'documentId' in (where as StudentRecord);
}

export default {
  beforeCreate(event: { params?: { data?: unknown } }) {
    hashData(event.params?.data);
  },

  beforeUpdate(event: { params?: { data?: unknown } }) {
    hashData(event.params?.data);
  },

  afterFindMany(event: { params?: unknown; result?: unknown }) {
    if (Array.isArray(event.result) && !isInternalDocumentQuery(event.params)) {
      for (const entry of event.result) {
        if (entry && typeof entry === 'object') {
          maskRecord(entry as StudentRecord);
        }
      }
    }
  },
};
