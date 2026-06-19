// Scope and database-resource logic. Pure functions — no I/O, unit-friendly.
// Security-critical: keep these implementations exactly as specified.

// The category of a scope is the substring before ":" (e.g. "db" for "db:query").
function category(scope: string): string {
  const i = scope.indexOf(":");
  return i === -1 ? scope : scope.slice(0, i);
}

// A scope string is a wildcard if it is the global "*" or a category wildcard
// like "db:*".
function isWildcard(scope: string): boolean {
  return scope === "*" || scope.endsWith(":*");
}

// hasScope: does a token's scope set satisfy a single required scope?
// True if the set contains "*", OR contains the exact required scope, OR
// contains the category wildcard of the required scope (e.g. "db:query" is
// satisfied by "db:*").
export function hasScope(tokenScopes: string[], required: string): boolean {
  if (tokenScopes.includes("*")) return true;
  if (tokenScopes.includes(required)) return true;
  const catWildcard = `${category(required)}:*`;
  return tokenScopes.includes(catWildcard);
}

// hasDatabase: may a token reach a given database id?
// True if the token's database set contains "*" OR contains the id.
export function hasDatabase(tokenDatabases: string[], dbId: string): boolean {
  return tokenDatabases.includes("*") || tokenDatabases.includes(dbId);
}

// Is a single child scope `s` covered by the parent scope set?
//   - parent has "*"                              → covered
//   - parent has the exact scope `s`              → covered
//   - s is NOT itself a wildcard and parent has   → covered
//     s's category wildcard (e.g. parent "db:*"
//     covers child "db:query")
//   - s IS a wildcard (e.g. "db:*") and parent    → covered
//     has that exact wildcard or "*"
function scopeCovered(s: string, parent: string[]): boolean {
  if (parent.includes("*")) return true;
  if (parent.includes(s)) return true;
  if (isWildcard(s)) {
    // s is a category wildcard like "db:*": only "*" or the exact wildcard
    // (both already handled above) cover it.
    return false;
  }
  // s is a concrete scope: its category wildcard covers it.
  return parent.includes(`${category(s)}:*`);
}

// scopesSubset: is every scope in `child` covered by `parent`?
// Child may contain "*" ONLY if parent contains "*".
export function scopesSubset(child: string[], parent: string[]): boolean {
  if (child.includes("*") && !parent.includes("*")) return false;
  return child.every((s) => scopeCovered(s, parent));
}

// databasesSubset: is the child database set within the parent's reach?
// If parent contains "*" → any child allowed. Else child must NOT contain "*"
// and every id in child must be present in parent.
export function databasesSubset(child: string[], parent: string[]): boolean {
  if (parent.includes("*")) return true;
  if (child.includes("*")) return false;
  return child.every((id) => parent.includes(id));
}
