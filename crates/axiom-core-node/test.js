// Axiom Protocol Core — Node.js binding test
// Run: node test.js
// Requires: npm install, napi build

const fs = require('fs');
const path = require('path');

async function main() {
  let binding;
  try {
    binding = require('./index.js');
  } catch {
    binding = require('./axiom-core-node.linux-x64-gnu.node');
  }

  console.log(`axiom-core ${binding.version()}`);

  const vectorsPath = path.resolve(__dirname, '../../tests/test_vectors.json');
  const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

  const pubkeyHex = '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12';
  const pubkey = Buffer.from(pubkeyHex, 'hex');

  let passed = 0;
  for (const vec of vectors.vectors) {
    if (!vec.is_valid) continue;

    const cose = Buffer.from(vec.cose_hex, 'hex');
    const payloadBytes = binding.verify_ed25519(cose, pubkey);

    if (payloadBytes.toString('hex') !== vec.payload_cbor_hex) {
      console.error(`FAIL ${vec.name}: payload mismatch`);
      process.exit(1);
    }

    const payload = binding.decode_payload(payloadBytes);
    if (Buffer.from(payload.subject).toString('hex') !== vec.payload.subject_hex) {
      console.error(`FAIL ${vec.name}: subject mismatch`);
      process.exit(1);
    }

    passed++;
  }

  console.log(`${passed} test vectors PASS`);
}

main().catch(console.error);
