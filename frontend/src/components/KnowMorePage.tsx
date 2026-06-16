import { config } from "../lib/config";

interface Props {
  onBack: () => void;
}

export function KnowMorePage({ onBack }: Props) {
  return (
    <main className="know-more">
      <nav className="know-more__nav">
        <button className="secondary" onClick={onBack}>
          ← Back to journal
        </button>
      </nav>

      <article className="know-more__content">
        <h1>How your privacy is protected</h1>

        <section>
          <h2>The enclave (AMD SEV-SNP)</h2>
          <p>
            Your messages are processed inside a{" "}
            <strong>Confidential Space virtual machine</strong> on Google Cloud. The VM runs on AMD
            hardware with SEV-SNP (Secure Encrypted Virtualization – Secure Nested Paging), which
            means the memory of the VM is encrypted by the CPU and cannot be read — not by the
            cloud provider, not by the operator, not by any other process on the same host.
          </p>
        </section>

        <section>
          <h2>The image digest: open-source code, verifiably running</h2>
          <p>
            Everything that runs inside the enclave is fixed at image build time and hashed into a{" "}
            <strong>container image digest</strong> — a SHA-256 fingerprint of every byte of code
            and data in the image. Google's attestation service reads this digest off the hardware
            and signs it into the attestation token.
          </p>
          <p>
            This app expects exactly one digest:
          </p>
          <pre className="know-more__digest">
            {config.expectedImageDigest || "(no digest configured — cannot verify)"}
          </pre>
          <p>
            That digest is published in the open-source repository so you can build the image
            yourself and confirm it matches. If an attacker tried to run different code, the digest
            would differ and the badge would turn red.
          </p>
        </section>

        <section>
          <h2>Key binding: only the real enclave can read your messages</h2>
          <p>
            At boot the enclave generates a fresh <strong>HPKE keypair</strong> (X25519). It then
            asks the attestation service to bind the hash of that public key into the signed token (
            via <code>eat_nonce</code>). This means:
          </p>
          <ul>
            <li>
              The signed token proves which key the enclave is holding right now, without revealing
              the private key.
            </li>
            <li>
              Your browser encrypts every message to that key. Only the enclave — the software
              whose code matches the open-source digest — holds the private key that can decrypt it.
            </li>
            <li>
              If anyone swapped the key (a man-in-the-middle, a misconfigured proxy, a malicious
              operator), the badge would turn red with "Key not bound in attestation token".
            </li>
          </ul>
        </section>

        <section>
          <h2>What the operator can and cannot see</h2>
          <table className="know-more__table">
            <thead>
              <tr>
                <th>What</th>
                <th>Visible to operator?</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Your journal entries</td>
                <td>No — encrypted client-side, stored only in your browser</td>
              </tr>
              <tr>
                <td>Your chat messages</td>
                <td>No — HPKE-encrypted before leaving your device</td>
              </tr>
              <tr>
                <td>The model's replies</td>
                <td>No — encrypted inside the enclave for your browser only</td>
              </tr>
              <tr>
                <td>That you used the service</td>
                <td>Yes — network logs show connections to the API endpoint</td>
              </tr>
              <tr>
                <td>The proprietary model / harness code</td>
                <td>Yes — the operator loads it into the enclave at startup</td>
              </tr>
            </tbody>
          </table>
        </section>

        <section>
          <h2>Verify it yourself</h2>
          <p>
            The enclave code is{" "}
            <a
              href="https://github.com/afonsomota/tee-gcp-protected-ip"
              target="_blank"
              rel="noreferrer"
            >
              open source
            </a>
            . You can build it, check the image digest, and run{" "}
            <a
              href="https://github.com/afonsomota/tee-gcp-protected-ip/blob/main/scripts/verify-attestation.py"
              target="_blank"
              rel="noreferrer"
            >
              <code>scripts/verify-attestation.py</code>
            </a>{" "}
            to verify the attestation token outside the browser. Step-by-step instructions are in{" "}
            <a
              href="https://github.com/afonsomota/tee-gcp-protected-ip/blob/main/docs/verifying.md"
              target="_blank"
              rel="noreferrer"
            >
              the verify-it-yourself guide
            </a>{" "}
            and{" "}
            <a
              href="https://github.com/afonsomota/tee-gcp-protected-ip/blob/main/README.md"
              target="_blank"
              rel="noreferrer"
            >
              the repository README
            </a>
            .
          </p>
          <p>
            One honest caveat: this page is served to you by the operator, so the verification
            code running in your browser right now could itself be lying about what it checks.
            Trusting it is a trust-on-first-use bet. If you are paranoid (good!), don't rely on
            our hosted copy — clone the open-source repository and run the frontend yourself with{" "}
            <code>pnpm dev</code> against the same enclave. The code is identical and the
            verification is then yours, not ours.
          </p>
        </section>
      </article>
    </main>
  );
}
