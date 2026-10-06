/**
 * student controller
 */

import crypto from 'crypto';
import type { Context, Next } from 'koa';
import { factories } from '@strapi/strapi';
import type { Core } from '@strapi/types';

const coreController = factories.createCoreController('api::student.student');

type StudentRecord = Record<string, unknown>;

const noopNext: Next = async () => {};

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

function maskRecord(record: StudentRecord): StudentRecord {
  const masked = { ...record };

  if (typeof masked.name === 'string' && masked.name.length > 1) {
    masked.name = `${masked.name.charAt(0)}${'x'.repeat(Math.max(masked.name.length - 1, 2))}`;
  }

  if (typeof masked.mobile === 'string') {
    masked.mobile = maskDigits(masked.mobile);
  }

  if (typeof masked.cardid === 'string') {
    masked.cardid = maskDigits(masked.cardid);
  }

  if ('password' in masked) {
    masked.password = 'xxx';
  }

  return masked;
}

function hashBodyPassword(ctx: Context): void {
  const body = (ctx.request as unknown as { body?: StudentRecord }).body;
  const data = body?.data as StudentRecord | undefined;
  if (data && typeof data.password === 'string' && data.password.length > 0) {
    data.password = hashPassword(data.password);
  }
}

function maskResult(result: unknown): unknown {
  if (result === null || result === undefined) {
    return result;
  }

  const res = result as StudentRecord;
  if (!('data' in res)) {
    return result;
  }

  const data = res.data;
  if (Array.isArray(data)) {
    return { ...res, data: data.map((record) => maskRecord(record as StudentRecord)) };
  }

  if (data !== null && typeof data === 'object') {
    return { ...res, data: maskRecord(data as StudentRecord) };
  }

  return result;
}

export default ({ strapi }: { strapi: Core.Strapi }) => {
  const base = coreController({ strapi });
  const baseCreate = base.create.bind(base);
  const baseUpdate = base.update.bind(base);
  const baseFind = base.find.bind(base);
  const baseFindOne = base.findOne.bind(base);

  base.create = async (ctx: Context) => {
    hashBodyPassword(ctx);
    return maskResult(await baseCreate(ctx, noopNext));
  };

  base.update = async (ctx: Context) => {
    hashBodyPassword(ctx);
    return maskResult(await baseUpdate(ctx, noopNext));
  };

  base.find = async (ctx: Context) => {
    return maskResult(await baseFind(ctx, noopNext));
  };

  base.findOne = async (ctx: Context) => {
    return maskResult(await baseFindOne(ctx, noopNext));
  };

  return base;
};
