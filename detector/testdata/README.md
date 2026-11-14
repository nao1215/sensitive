Specification vectors

Bitcoin vectors: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki and https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki (BSD-2-Clause). BIP-350 supersedes v1+ Bech32 checksums. Testnet addresses are intentionally rejected by this mainnet-only detector.

Ethereum vectors: https://eips.ethereum.org/EIPS/eip-55 (CC0).

Other witness versions and non-P2TR v1 program lengths are intentionally outside the detector's documented scope; the corresponding valid BIP-350 addresses are rejection vectors here.

IBAN country lengths, BBAN patterns and examples: SWIFT IBAN Registry, release 103 (September 2026), https://www.swift.com/swift-resource/9606/download . Fixtures contain all 89 registered country formats. National BBAN account checksums are not validated by this library.

PAN/Luhn examples: Stripe testing cards, https://docs.stripe.com/testing#cards . These are synthetic test numbers, not live credentials.
