/**
 * DOM Mail cyberpunk/hacker culture domain generator.
 *
 * Generates domains and email addresses fitting:
 * - Hacker culture (leet, crypto, anon, defcon, etc.)
 * - Cyberpunk aesthetics (neon, synth, chrome, void, etc.)
 * - Privacy/counterculture (nomo, zero, null, ghost, etc.)
 * - Futuristic minimalism (io, dev, sys, net, etc.)
 */

const TLD = [
  'io', 'dev', 'net', 'org', 'space', 'link', 'zone', 'xyz',
  'tech', 'app', 'cc', 'sh', 'to', 'is', 'pm', 'gg',
  'onion', 'i2p', 'bit', 'lib', 'git', 'src', 'bin', 'sys',
  'nexus', 'void', 'null', 'zero', 'anon', 'dark', 'deep',
];

const PREFIXES = [
  // Hacker/leet
  'null', 'void', 'zero', 'root', 'admin', 'sysop', 'daemon', 'kernel',
  'shell', 'term', 'cli', 'bash', 'zsh', 'vim', 'emacs', 'nano',
  'crypto', 'cipher', 'hash', 'salt', 'nonce', 'key', 'sig', 'cert',
  'anon', 'ghost', 'shadow', 'phantom', 'specter', 'wraith', 'shade',
  'nomo', 'nobody', 'none', 'nil', 'empty', 'blank', 'hidden', 'masked',
  'tor', 'i2p', 'freed', 'libre', 'open', 'free', 'libre', 'public',
  'defcon', 'blackhat', 'whitehat', 'greyhat', 'redteam', 'blueteam',
  'pentest', 'exploit', 'payload', 'shellcode', 'rop', 'jop', 'gadget',
  'buffer', 'overflow', 'injection', 'xss', 'csrf', 'sqli', 'rce',
  'mitm', 'dns', 'bgp', 'ospf', 'mpls', 'vlan', 'vxlan', 'gre',

  // Cyberpunk/neon
  'neon', 'synth', 'chrome', 'cyber', 'netrun', 'deck', 'ice', 'blackice',
  'deckard', 'roy', 'batty', 'priss', 'zion', 'matrix', 'simulacra',
  'replicant', 'android', 'cyborg', 'augment', 'implant', 'chrome',
  'neural', 'synaptic', 'cortex', 'wetware', 'hardware', 'software',
  'firmware', 'malware', 'ransom', 'cryptolocker', 'wiper', 'wiper',
  'tokyo', 'chiba', 'shibuya', 'shinjuku', 'akihabara', 'roppongi',
  'night', 'city', 'rain', 'neon', 'hologram', 'projection', 'AR', 'VR',
  'mr', 'xr', 'metaverse', 'meatspace', 'cyberspace', 'dataspace',

  // Privacy/counterculture
  'nolog', 'notrack', 'nodata', 'nosurveillance', 'noprofile', 'noads',
  'encrypted', 'e2e', 'p2p', 'mesh', 'federated', 'decentralized',
  'autonomous', 'sovereign', 'selfhosted', 'airgapped', 'offline',
  'localfirst', 'privacyfirst', 'securityfirst', 'freedomfirst',
  'resist', 'defy', 'subvert', 'undermine', 'circumvent', 'bypass',
  'tor', 'onion', 'i2p', 'freenet', 'zeronet', 'ipfs', 'dat', 'ssb',
  'nostr', 'activitypub', 'matrix', 'xmpp', 'signal', 'session',

  // Minimalist/futuristic
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  'aa', 'bb', 'cc', 'dd', 'ee', 'ff', 'gg', 'hh', 'ii', 'jj',
  'sys', 'net', 'dev', 'ops', 'sec', 'inf', 'eng', 'dev', 'qa',
  'prod', 'staging', 'test', 'ci', 'cd', 'git', 'svn', 'hg',
  'api', 'rpc', 'grpc', 'rest', 'ws', 'wss', 'mqtt', 'coap',
];

const SUFFIXES = [
  // Tech/Unix
  'd', 'bin', 'sbin', 'usr', 'etc', 'var', 'tmp', 'opt', 'lib', 'lib64',
  'src', 'include', 'share', 'man', 'doc', 'info', 'locale', 'zoneinfo',
  'dev', 'proc', 'sys', 'run', 'mnt', 'media', 'srv', 'home', 'root',
  'cfg', 'conf', 'config', 'ini', 'yaml', 'toml', 'json', 'xml',
  'log', 'pid', 'lock', 'socket', 'pipe', 'fifo', 'null', 'zero',
  'random', 'urandom', 'tty', 'pts', 'shm', 'fd', 'stdin', 'stdout', 'stderr',

  // Crypto
  'pub', 'priv', 'key', 'pem', 'der', 'crt', 'csr', 'pfx', 'p12',
  'rsa', 'dsa', 'ecdsa', 'ed25519', 'x25519', 'curve25519', 'secp256k1',
  'aes', 'chacha', 'poly', 'gcm', 'ctr', 'cbc', 'ecb', 'ofb', 'cfb',
  'sha', 'md5', 'blake', 'keccak', 'shake', 'hmac', 'hkdf', 'pbkdf',
  'argon', 'scrypt', 'bcrypt', 'pbkdf2', 'totp', 'hotp', 'otp',

  // Network
  'tcp', 'udp', 'ip', 'ipv4', 'ipv6', 'icmp', 'igmp', 'arp', 'rarp',
  'dns', 'dhcp', 'tftp', 'ftp', 'sftp', 'scp', 'rsync', 'ssh', 'telnet',
  'http', 'https', 'ws', 'wss', 'grpc', 'quic', 'http2', 'http3',
  'tls', 'ssl', 'dtls', 'srtp', 'zrtp', 'otr', 'omemo', 'pgp', 'gpg',

  // Abstract
  'node', 'edge', 'core', 'hub', 'spoke', 'mesh', 'star', 'ring', 'bus',
  'tree', 'graph', 'dag', 'chain', 'block', 'tx', 'utxo', 'mempool',
  'validator', 'miner', 'staker', 'delegator', 'oracle', 'relay',
  'bridge', 'gateway', 'proxy', 'vpn', 'tor', 'i2p', 'exit', 'entry',
  'guard', 'middle', 'exit', 'hsdir', 'intro', 'rendezvous',
];

const WORDLISTS = {
  hacker: PREFIXES.filter(p => ['null','void','zero','root','admin','daemon','kernel','shell','crypto','cipher','hash','anon','ghost','shadow','tor','defcon','pentest','exploit','buffer','overflow','mitm'].includes(p)),
  cyberpunk: PREFIXES.filter(p => ['neon','synth','chrome','cyber','netrun','deck','ice','deckard','zion','matrix','replicant','cyborg','neural','tokyo','night','hologram'].includes(p)),
  privacy: PREFIXES.filter(p => ['nolog','notrack','encrypted','e2e','p2p','mesh','autonomous','sovereign','airgapped','tor','onion','i2p','nostr','signal'].includes(p)),
  minimal: PREFIXES.filter(p => p.length <= 3 || ['sys','net','dev','ops','sec','api','rpc','git','ci','cd'].includes(p)),
};

function shuffle(array) {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function randomElement(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomElements(arr, count) {
  return shuffle(arr).slice(0, count);
}

export class DomainGenerator {
  constructor(opts = {}) {
    this.culture = opts.culture || 'mixed';
    this.separator = opts.separator || '.';
    this.includeSubdomain = opts.includeSubdomain !== false;
  }

  generateLocalPart(style = 'random') {
    const styles = {
      leet: () => this._leetSpeak(randomElement(PREFIXES)),
      minimal: () => randomElement(WORDLISTS.minimal),
      crypto: () => randomElement(PREFIXES.filter(p => ['crypto','cipher','hash','key','sig','cert','rsa','ed25519','x25519','aes','chacha','sha','blake'].includes(p))),
      cyberpunk: () => randomElement(WORDLISTS.cyberpunk),
      privacy: () => randomElement(WORDLISTS.privacy),
      unix: () => randomElement(SUFFIXES.filter(s => ['bin','etc','var','tmp','dev','proc','sys','cfg','log','pid','null','random'].includes(s))),
      network: () => randomElement(SUFFIXES.filter(s => ['tcp','udp','ip','dns','ssh','tls','http','ws','grpc','quic','tor','i2p','vpn','proxy'].includes(s))),
      abstract: () => randomElement(SUFFIXES.filter(s => ['node','edge','core','hub','mesh','chain','block','tx','validator','oracle','bridge','gateway'].includes(s))),
      random: () => randomElement([...PREFIXES, ...SUFFIXES]),
    };
    const generator = styles[style] || styles.random;
    return generator().toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 32);
  }

  _leetSpeak(word) {
    const map = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7', l: '1', g: '9', b: '8' };
    return word.split('').map(c => map[c] || c).join('');
  }

  generateDomain(style = 'random') {
    const tld = randomElement(TLD);
    const prefix = this.generateLocalPart(style);
    const suffix = randomElement(SUFFIXES).toLowerCase().replace(/[^a-z0-9]/g, '');
    const domain = `${prefix}${this.separator}${suffix}.${tld}`;
    return domain.length > 253 ? domain.slice(0, 253) : domain;
  }

  generateEmail(style = 'random') {
    const local = this.generateLocalPart(style);
    const domain = this.generateDomain(style);
    return `${local}@${domain}`;
  }

  generateIdentity(style = 'random') {
    const local = this.generateLocalPart(style);
    const domain = this.generateDomain(style);
    const name = this._generateName(style);
    return {
      name,
      local,
      domain,
      address: `${local}@${domain}`,
    };
  }

  _generateName(style) {
    const names = {
      leet: ['r00t', '4dm1n', 'd43m0n', 'k3rn3l', 'sh3ll', 'cr1pt0', '4n0n', 'gh0st'],
      cyberpunk: ['Neon', 'Synth', 'Chrome', 'Netrun', 'Deck', 'Ice', 'Zero', 'Void', 'Ghost', 'Shadow'],
      privacy: ['NoLog', 'NoTrack', 'Encrypted', 'Anonymous', 'Sovereign', 'Airgapped', 'Offline', 'LocalFirst'],
      minimal: ['a', 'b', 'x', 'y', 'z', 'sys', 'net', 'dev', 'ops', 'sec'],
      random: ['Nova', 'Echo', 'Pulse', 'Signal', 'Byte', 'Bit', 'Flux', 'Vector', 'Scalar', 'Matrix'],
    };
    const list = names[style] || names.random;
    return randomElement(list);
  }

  generateBatch(count, style = 'random') {
    const results = [];
    for (let i = 0; i < count; i++) {
      results.push(this.generateIdentity(style));
    }
    return results;
  }

  static getCultures() {
    return ['leet', 'cyberpunk', 'privacy', 'minimal', 'random'];
  }
}

export function createDomainGenerator(opts = {}) {
  return new DomainGenerator(opts);
}

export const DOMAIN_CULTURES = {
  leet: { name: 'Leet/Hacker', description: '1337 speak, kernel, shell, crypto terms' },
  cyberpunk: { name: 'Cyberpunk/Neon', description: 'Neon, synth, chrome, netrunner, Tokyo nights' },
  privacy: { name: 'Privacy/Counterculture', description: 'NoLog, NoTrack, Encrypted, Sovereign, Tor, I2P' },
  minimal: { name: 'Minimalist/Futuristic', description: 'sys, net, dev, ops, sec, api, git, ci' },
  mixed: { name: 'Mixed/Random', description: 'Random selection from all cultures' },
};