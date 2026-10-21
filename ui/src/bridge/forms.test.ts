import { describe, expect, it } from 'vitest';
import { ACCOUNT, ACCOUNT_CHECKSUMMED, DEPOSIT_ADDRESS } from '../dev/fixture';
import { readDeposit, readHumid, readPayTo, readRedeem } from './forms';

describe('deposit form', () => {
  it('takes an unconfidential segwit address and an amount in whole bridge units', () => {
    const d = readDeposit(DEPOSIT_ADDRESS, '0.0025');
    expect(d.errors).toEqual({});
    expect(d.address).toBe(DEPOSIT_ADDRESS);
    expect(d.units).toBe(250_000n);
    expect(d.wei).toBe(2_500_000_000_000_000n);
  });

  it('gives neither value nor error for empty fields', () => {
    expect(readDeposit('', ' ')).toEqual({ errors: {} });
  });

  it('refuses a confidential address, an amount under the minimum and one finer than a unit, with the shared rules\' words', () => {
    expect(readDeposit('tlq1qqexample', '').errors.recipient).toBeTruthy();
    expect(readDeposit('', '0.0001').errors.amount).toBeTruthy();
    expect(readDeposit('', '0.001000000001').errors.amount).toBeTruthy();
  });
});

describe('redeem form', () => {
  it('defaults the recipient to the connected account', () => {
    expect(readRedeem({ recipient: '', amount: '' }, ACCOUNT).recipient).toBe(ACCOUNT);
  });

  it('takes a typed address only checksummed, unless it is the connected account: a burn cannot be redirected', () => {
    expect(readRedeem({ recipient: ACCOUNT_CHECKSUMMED, amount: '' }, null).recipient).toBe(ACCOUNT);
    expect(readRedeem({ recipient: ACCOUNT, amount: '' }, null).recipientError).toMatch(/checksummed/);
    expect(readRedeem({ recipient: ACCOUNT, amount: '' }, ACCOUNT).recipient).toBe(ACCOUNT);
  });

  it('reads the amount in units of 10^-8', () => {
    expect(readRedeem({ recipient: '', amount: '0.001' }, null).units).toBe(100_000n);
    expect(readRedeem({ recipient: '', amount: 'abc' }, null).amountError).toBeTruthy();
  });

  it('pays the recipient unless another checked address is given', () => {
    expect(readPayTo('  ', ACCOUNT)).toEqual({ payTo: null });
    expect(readPayTo(ACCOUNT_CHECKSUMMED, null).payTo).toBe(ACCOUNT);
    expect(readPayTo('0x1234', null).error).toBeTruthy();
  });
});

describe('Humid address', () => {
  it('takes the unconfidential tex1q address and refuses the confidential one with a pointer to the right tab', () => {
    expect(readHumid(DEPOSIT_ADDRESS).claim?.address).toBe(DEPOSIT_ADDRESS);
    expect(readHumid('tlq1qq0000').error).toMatch(/Unconfidential/);
    expect(readHumid('')).toEqual({});
  });
});
