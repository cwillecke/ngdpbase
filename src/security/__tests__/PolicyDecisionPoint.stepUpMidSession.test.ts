/**
 * #2237 — a second factor enrolled in a session raises what step-up asks of
 * that session. An admin with a password and no passkey or app signs in held
 * at AAL1 (nothing can reach AAL2). Adding an authenticator app means the
 * account can reach AAL2 from then on, so removing the app in the same session
 * asks for the password and a code, as a fresh sign-in does (#2236).
 *
 * The real AuthManager (with FileCredentialsProvider, in a temp directory that
 * is all that is removed) and the real PDP; the subject is built as the session
 * middleware in `app.ts` builds it. No seed or password hash is printed.
 */
vi.unmock('../../providers/FileCredentialsProvider');

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Secret, TOTP } from 'otpauth';
import PolicyDecisionPoint from '../PolicyDecisionPoint';
import AuthManager from '../../managers/AuthManager.js';
import { CREDENTIALS_KEY_ENV } from '../../providers/BaseCredentialsProvider.js';

const KEY = 'test-credentials-key-not-a-secret';
const codeFor = (seed: string, at: number) => new TOTP({ secret: Secret.fromBase32(seed), digits: 6, period: 30, algorithm: 'SHA1' }).generate({ timestamp: at });
const signInAt = (aal: 1 | 2) => {
  const at = new Date().toISOString();
  const factors = [{ provider: 'password', amr: ['pwd'], aal: 1, at }, ...(aal === 2 ? [{ provider: 'totp', amr: ['otp'], aal: 1, at }] : [])];
  return { provider: 'password', factors, amr: factors.flatMap(f => f.amr), aal, acr: `aal${aal}`, mfa: aal === 2, at };
};

describe('#2237 step-up re-reads what the account can reach', () => {
  let dir: string;
  const savedKey = process.env[CREDENTIALS_KEY_ENV];

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ngdpbase-2237-'));
    process.env[CREDENTIALS_KEY_ENV] = KEY;
  });

  afterEach(() => {
    if (savedKey === undefined) delete process.env[CREDENTIALS_KEY_ENV]; else process.env[CREDENTIALS_KEY_ENV] = savedKey;
    // Only the per-test temp directory — never a live data tree.
    fs.rmSync(dir, { recursive: true, force: true });
  });

  async function setUp() {
    const config: Record<string, unknown> = {
      'ngdpbase.auth.factors': [
        { authproviderid: 'password', primary: true, amr: ['pwd'], aal: 1, enabled: true },
        { authproviderid: 'totp', primary: false, amr: ['otp'], aal: 1, enabled: true, preference: 3 }
      ],
      'ngdpbase.auth.step-up': { 'max-age-minutes': 60 },
      'ngdpbase.permissions.definitions': { 'account-security': { description: 'own account', 'step-up': true } }
    };
    const managers: Record<string, unknown> = {
      ConfigurationManager: {
        getProperty: (k: string, d: unknown) => (k in config ? config[k] : d),
        getCustomProperty: () => undefined,
        getResolvedDataPath: (k: string, d: string) => (k === 'ngdpbase.auth.credentials.file' ? path.join(dir, 'users', 'credentials.json') : d),
        isBaseUrlExplicit: () => false,
        getBaseURL: () => 'http://wiki.example.com',
        getApplicationName: () => 'Willeke Family'
      },
      // Enrolling is the person's own right here; the decision under test is the real PDP's, below.
      PolicyDecisionPoint: { permits: () => Promise.resolve(true), holds: () => Promise.resolve(true) },
      PolicyEvaluator: { evaluateAccess: () => Promise.resolve({ allowed: true, hasDecision: true, policyName: 'grant' }) },
      RoleManager: { roleRequiredAal: () => ({ admin: 2, 'vault-owner': 0 }), operatorRequiredAal: () => ({}) },
      UserManager: { getUser: (u: string) => Promise.resolve({ username: u }) },
      AuditManager: { logAuditEvent: () => Promise.resolve('evt'), logAuthentication: () => Promise.resolve('evt') }
    };
    const engine = { getManager: (n: string) => managers[n] ?? null };
    const am = new AuthManager(engine as never);
    await am.initialize();
    managers.AuthManager = am;
    return { am, pdp: new PolicyDecisionPoint(engine) };
  }

  /** The request subject as the session middleware builds it, for a session signed in with `signIn`. */
  async function sessionSubject(am: AuthManager, signIn: ReturnType<typeof signInAt>) {
    const roles = ['admin', 'vault-owner'];
    const { now: aalCap } = await am.aalReachFor('jim');
    const stepDown = am.rolesAtSignIn(roles, signIn.aal, aalCap);
    return { username: 'jim', isAuthenticated: true, roles: stepDown.kept, stepUpRoles: roles, aalCap, signIn } as never;
  }

  test('adding an app, then removing it in the same session, asks for the code', async () => {
    const { am, pdp } = await setUp();
    const signIn = signInAt(1);

    // Nothing can reach AAL2 yet: the session is held at AAL1 and the password is enough.
    expect(await pdp.permits(await sessionSubject(am, signIn), 'account-security')).toBe(true);

    const owner = { username: 'jim', roles: ['admin'], isAuthenticated: true, signIn } as never;
    const { seed, pending } = await am.totpEnrolmentStart(owner, 'jim');
    expect(await am.totpEnrolmentConfirm(owner, 'jim', pending, codeFor(seed, Date.now()), 'Phone')).toEqual(expect.any(String));

    // The account can now reach AAL2, so the same session is asked for the code.
    expect(await pdp.permits(await sessionSubject(am, signIn), 'account-security')).toBe(false);
    expect(await pdp.decide(await sessionSubject(am, signIn), { action: 'account-security' })).toMatchObject({ permit: false, reason: 'step-up' });
  });

  test('after the password and code, the same session is permitted', async () => {
    const { am, pdp } = await setUp();
    const owner = { username: 'jim', roles: ['admin'], isAuthenticated: true, signIn: signInAt(1) } as never;
    const { seed, pending } = await am.totpEnrolmentStart(owner, 'jim');
    await am.totpEnrolmentConfirm(owner, 'jim', pending, codeFor(seed, Date.now()), 'Phone');
    expect(await pdp.permits(await sessionSubject(am, signInAt(2)), 'account-security')).toBe(true);
  });
});
