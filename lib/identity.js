// Generated identities: the values typed into forms when no canary
// mailbox is configured. The pools and styles come from the fingerprint
// profile (core/fingerprint.js), so each installation types differently.

const FIRST = ["james", "maria", "david", "sarah", "michael", "laura", "daniel", "emma", "robert", "anna", "thomas", "julia", "kevin", "claire",
  "steven", "nina", "paul", "olivia", "mark", "sofia", "peter", "helen", "andrew", "rachel", "brian", "megan", "eric", "diana", "jason", "karen",
  "adam", "lucy", "ryan", "grace", "simon", "irene", "victor", "hannah", "omar", "priya", "lucas", "elena", "marco", "chloe", "ivan", "nadia"];
const LAST = ["morgan", "reyes", "patel", "nguyen", "okafor", "fischer", "rossi", "dubois", "novak", "silva", "keller", "walsh", "hughes",
  "bennett", "carter", "foster", "harper", "lawson", "mendes", "porter", "quinn", "russo", "sandoval", "tanaka", "turner", "vogel", "weber",
  "young", "brooks", "coleman", "dalton", "ellis", "garner", "hale", "ingram", "jensen", "kaur", "lindqvist", "mercer", "nolan", "ortiz"];
const WORDS = ["harbor", "summit", "north", "cedar", "bright", "lumen", "vertex", "atlas", "maple", "river", "stone", "pioneer", "civic",
  "beacon", "crest", "delta", "ember", "falcon", "granite", "horizon", "iron", "juniper", "keystone", "lake", "meridian", "oak", "pine",
  "quarry", "ridge", "sterling", "tidal", "union", "valley", "willow", "apex", "bay", "canyon", "grove", "field", "point"];
const SUFFIX = ["group", "partners", "systems", "solutions", "consulting", "logistics", "health", "capital", "labs", "industries", "services", "works"];
const TLDS = ["com", "com", "com", "net", "co", "io", "org"];
const EMAIL_STYLES = {
  "first.last": (f, l) => `${f}.${l}`, flast: (f, l) => `${f[0]}${l}`, firstlast: (f, l) => `${f}${l}`, first_last: (f, l) => `${f}_${l}`,
  "last.first": (f, l) => `${l}.${f}`, firstl: (f, l) => `${f}${l[0]}`, "first.last##": (f, l, r) => `${f}.${l}${digits(2, r)}`,
};
const PASSWORD_STYLES = ["Season####!", "Word##Word!", "Name@####", "Word.Word##", "WordWord#!#", "Month####$"];
const SEASONS = ["Spring", "Summer", "Autumn", "Winter"];
const MONTHS = ["January", "March", "April", "June", "August", "October", "November", "December"];
const PW_WORDS = ["Sunset", "Coffee", "Garden", "Rocket", "Silver", "Thunder", "Ocean", "Forest", "Marble", "Piano", "Tiger", "Velvet", "Harbor", "Comet"];

const pick = (a, r) => a[Math.floor(r() * a.length)];
const digits = (n, r) => Array.from({ length: n }, () => Math.floor(r() * 10)).join("");
const sample = (a, n, r) => { const c = a.slice(); for (let i = c.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [c[i], c[j]] = [c[j], c[i]]; } return c.slice(0, n); };
const cap = (s) => s[0].toUpperCase() + s.slice(1);

// A profile's generator spec: subsets of the pools, a few company
// domains and styles. `r` is the profile's seeded random source.
function newSpec(r) {
  const domains = Array.from({ length: 3 + Math.floor(r() * 3) }, () => {
    const a = pick(WORDS, r), b = r() < 0.5 ? pick(WORDS, r) : pick(SUFFIX, r);
    return `${a}${r() < 0.35 ? "-" : ""}${b}.${pick(TLDS, r)}`;
  });
  return {
    firstNames: sample(FIRST, 14, r), lastNames: sample(LAST, 14, r), domains: [...new Set(domains)],
    emailStyles: sample(Object.keys(EMAIL_STYLES), 2, r), passwordStyles: sample(PASSWORD_STYLES, 2, r),
  };
}

function email(spec, r = Math.random) {
  const f = pick(spec.firstNames, r), l = pick(spec.lastNames, r);
  const style = EMAIL_STYLES[pick(spec.emailStyles, r)] || EMAIL_STYLES["first.last"];
  return `${style(f, l, r)}@${pick(spec.domains, r)}`;
}

function password(spec, r = Math.random) {
  return pick(spec.passwordStyles, r)
    .replace("Season", pick(SEASONS, r)).replace("Month", pick(MONTHS, r)).replace("Name", cap(pick(spec.firstNames, r)))
    .replace(/Word/g, () => pick(PW_WORDS, r)).replace(/#/g, () => digits(1, r));
}

// Wallet recovery phrases: 12 words from the BIP39 list (long, uncommon
// ones, so finding three of them in a request means the phrase went there).
const SEED_WORDS = ["abandon", "ability", "absorb", "abstract", "academy", "account", "acoustic", "acquire", "balance", "bamboo", "banana",
  "blanket", "cabbage", "cactus", "canyon", "carbon", "castle", "dolphin", "document", "dragon", "elephant", "fabric", "festival", "glimpse",
  "gorilla", "harvest", "hospital", "inherit", "journey", "kangaroo", "kitchen", "lobster", "mammal", "mushroom", "napkin", "nephew",
  "october", "orchard", "panther", "penguin", "pyramid", "quantum", "rabbit", "raccoon", "saddle", "salmon", "squirrel", "tobacco",
  "tornado", "umbrella", "vintage", "walnut", "wizard"];
const seedPhrase = (r = Math.random) => sample(SEED_WORDS, 12, r).join(" ");

const name = (spec, r = Math.random) => `${cap(pick(spec.firstNames, r))} ${cap(pick(spec.lastNames, r))}`;

module.exports = { newSpec, email, password, name, seedPhrase };
