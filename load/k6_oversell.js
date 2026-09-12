// k6 variant of load/oversell_proof.py — same invariant, plus a latency profile.
//
//   k6 run -e BASE_URL=http://localhost:8000 -e FLIGHT_ID=<uuid> load/k6_oversell.js
//
// Start the API with RATE_LIMIT_ENABLED=false first: the limiter exists to stop
// exactly this traffic shape, and leaving it on measures the limiter rather than
// the seat locking.
//
// Create the flight and print its id with:
//   python -c "import asyncio;from load.oversell_proof import _make_flight;\
//              print(asyncio.run(_make_flight(50))[0])"

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';
const FLIGHT_ID = __ENV.FLIGHT_ID;
const SEATS = parseInt(__ENV.SEATS || '50', 10);
const PASSWORD = 'correct-horse-battery-staple';

const confirmed = new Counter('bookings_confirmed');
const lostRace = new Counter('races_lost');
const serverErrors = new Counter('server_errors');

export const options = {
  scenarios: {
    stampede: {
      // Everyone arrives at once, which is the point.
      executor: 'shared-iterations',
      vus: 200,
      iterations: 400,
      maxDuration: '2m',
    },
  },
  thresholds: {
    // The invariant, expressed as a threshold: never more bookings than seats.
    bookings_confirmed: [`count<=${SEATS}`],
    server_errors: ['count==0'],
    http_req_failed: ['rate<1.0'],
    http_req_duration: ['p(95)<2000'],
  },
};

function jsonHeaders(token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
}

export function setup() {
  if (!FLIGHT_ID) {
    throw new Error('FLIGHT_ID is required — see the header comment.');
  }
  // A small pool of accounts, each with its own card token so the
  // card-across-accounts fraud rule does not fire during a load run.
  const pool = [];
  for (let i = 0; i < 8; i++) {
    const response = http.post(
      `${BASE_URL}/auth/register`,
      JSON.stringify({ email: `k6-${randomString(12)}@example.com`, password: PASSWORD }),
      { headers: jsonHeaders() },
    );
    if (response.status !== 201) {
      throw new Error(`registration failed: ${response.status} ${response.body}`);
    }
    pool.push({ token: response.json('access_token'), card: `tok_test_k6${String(i).padStart(4, '0')}0000` });
  }
  return { pool };
}

export default function (data) {
  const account = data.pool[__VU % data.pool.length];
  const seatNo = `${Math.floor((__ITER % SEATS) / 6) + 10}${'ABCDEF'[(__ITER % SEATS) % 6]}`;

  const held = http.post(
    `${BASE_URL}/holds`,
    JSON.stringify({ flight_id: FLIGHT_ID, seat_no: seatNo }),
    { headers: jsonHeaders(account.token), tags: { name: 'POST /holds' } },
  );

  if (held.status >= 500) serverErrors.add(1);
  if (held.status !== 201) {
    // Losing a race is a normal outcome, not an error.
    check(held, { 'hold conflict is a 409': (r) => r.status === 409 || r.status === 429 });
    lostRace.add(1);
    return;
  }

  const booked = http.post(
    `${BASE_URL}/bookings`,
    JSON.stringify({
      hold_ids: [held.json('hold_id')],
      passengers: [{ given_name: 'Load', family_name: 'Racer' }],
      card_token: account.card,
    }),
    {
      headers: { ...jsonHeaders(account.token), 'Idempotency-Key': randomString(24) },
      tags: { name: 'POST /bookings' },
    },
  );

  if (booked.status >= 500) serverErrors.add(1);
  if (booked.status === 201) confirmed.add(1);

  check(booked, {
    'booking is 201 or a clean conflict': (r) =>
      [201, 402, 403, 409, 429].includes(r.status),
  });
}
