// ZEEX transform — JSX in, render IR out. Runs inside QuickJS at build time.
//
// This is the whole reason the engine is vendored: templates are authored as HTML+JSX, and lowering them
// needs a JS interpreter. Doing it here means no Node, no npm, no Babel — the build already carries an
// engine, and this is a script it runs.
//
// Input:  one template source string (HTML + the JSX subset below).
// Output: JSON — an array of ops the Zig side turns into `Builder` calls.
//
// The subset, deliberately small and closed. Anything outside it is an error naming the line, not a
// silent misparse:
//
//   <div class="card" id={props.id}>…</div>      element, static and interpolated attributes
//   <br/>                                        self-closing and void elements
//   {props.title}                                member path — the only expression form
//   {__raw(props.html)}                          verbatim interpolation, explicit and greppable
//   {props.show && <p>…</p>}                     conditional
//   {props.items.map(function (item) { … })}     iteration, and the ES5 arrow form
//   {props.items.map(item => <li>{item}</li>)}
//
// Interpolation is a *path*, never an expression, so the generated Zig reads a field of the props struct
// and a typo becomes a Zig compile error rather than a blank spot on a page. Text is escaped; `__raw` is
// the one way to say otherwise.

function fail(message, line) {
  throw new Error("zeex: " + message + (line ? " (line " + line + ")" : ""));
}

var VOID_TAGS = {
  area: 1, base: 1, br: 1, col: 1, embed: 1, hr: 1, img: 1, input: 1,
  link: 1, meta: 1, param: 1, source: 1, track: 1, wbr: 1,
};

function lineAt(source, index) {
  var line = 1;
  for (var i = 0; i < index && i < source.length; i++) if (source.charCodeAt(i) === 10) line++;
  return line;
}

// A path like `props.a.b` becomes ["a","b"]; `item` inside a loop becomes ["$item"]. Anything else is
// refused, because a general expression language is exactly what this design does not have.
function parsePath(text, loopVars, index, source) {
  var raw = text.trim();
  if (raw.length === 0) fail("empty interpolations are not allowed", lineAt(source, index));

  var parts = raw.split(".");
  var head = parts[0].trim();
  var path = [];

  if (head === "props") {
    if (parts.length < 2) fail("expected a property of `props`, not `props` itself", lineAt(source, index));
    for (var i = 1; i < parts.length; i++) path.push(parts[i].trim());
  } else if (loopVars[head] === 1) {
    if (parts.length !== 1) fail("a loop variable has no properties here: " + raw, lineAt(source, index));
    path.push("$" + head);
  } else {
    fail("only `props.name`, a loop variable, or `__raw(...)` may appear in braces; found `" + raw + "`", lineAt(source, index));
  }

  return path;
}

function Parser(source) {
  this.source = source;
  this.at = 0;
  this.loopVars = {};
}

Parser.prototype.fail = function (message) {
  fail(message, lineAt(this.source, this.at || 0));
};

Parser.prototype.peek = function () {
  return this.source[this.at];
};

Parser.prototype.startsWith = function (text) {
  return this.source.startsWith(text, this.at);
};

Parser.prototype.take = function (text) {
  if (!this.startsWith(text)) this.fail("expected `" + text + "`");
  this.at += text.length;
};

Parser.prototype.skipSpace = function () {
  while (this.at < this.source.length && /\s/.test(this.source[this.at])) this.at++;
};

Parser.prototype.readName = function () {
  var start = this.at;
  while (this.at < this.source.length && /[A-Za-z0-9_\-:.]/.test(this.source[this.at])) this.at++;
  if (start === this.at) this.fail("expected a name");
  return this.source.slice(start, this.at);
};

// Read up to the matching `}` of an interpolation, honouring nested braces and quoted strings so a `}`
// inside a string does not end it.
Parser.prototype.readBraced = function () {
  var start = this.at;
  var depth = 0;
  while (this.at < this.source.length) {
    var ch = this.source[this.at];
    if (ch === '"' || ch === "'") {
      var quote = ch;
      this.at++;
      while (this.at < this.source.length && this.source[this.at] !== quote) {
        if (this.source[this.at] === "\\") this.at++;
        this.at++;
      }
      this.at++;
      continue;
    }
    if (ch === "{") depth++;
    if (ch === "}") {
      depth--;
      if (depth === 0) {
        var body = this.source.slice(start + 1, this.at);
        this.at++;
        return body;
      }
    }
    this.at++;
  }
  this.at = start;
  this.fail("unterminated interpolation");
};

Parser.prototype.readString = function () {
  var quote = this.source[this.at];
  this.at++;
  var out = "";
  while (this.at < this.source.length && this.source[this.at] !== quote) {
    if (this.source[this.at] === "\\") {
      this.at++;
      out += this.source[this.at];
      this.at++;
      continue;
    }
    out += this.source[this.at];
    this.at++;
  }
  this.at++;
  return out;
};

Parser.prototype.parseChildren = function (closingTag) {
  var children = [];
  var text = "";

  var flush = function (self) {
    if (text.length > 0) {
      children.push({ op: "text", value: text });
      text = "";
    }
  };

  while (this.at < this.source.length) {
    if (this.startsWith("</")) {
      flush(this);
      if (!closingTag) this.fail("closing tag without an opening tag");
      this.take("</");
      var name = this.readName();
      this.skipSpace();
      this.take(">");
      if (name !== closingTag) this.fail("expected </" + closingTag + "> but found </" + name + ">");
      return children;
    }

    if (this.startsWith("<")) {
      flush(this);
      children.push(this.parseElement());
      continue;
    }

    if (this.startsWith("{")) {
      flush(this);
      children.push(this.parseBraced());
      continue;
    }

    text += this.source[this.at];
    this.at++;
  }

  if (closingTag) this.fail("unterminated <" + closingTag + ">");
  flush(this);
  return children;
};

Parser.prototype.parseElement = function () {
  this.take("<");
  var tag = this.readName();
  var attrs = [];
  var selfClosing = false;

  while (true) {
    this.skipSpace();
    if (this.startsWith("/>")) {
      this.take("/>");
      selfClosing = true;
      break;
    }
    if (this.startsWith(">")) {
      this.take(">");
      break;
    }
    if (this.at >= this.source.length) this.fail("unterminated <" + tag + ">");

    var name = this.readName();
    this.skipSpace();
    if (this.peek() === "=") {
      this.at++;
      this.skipSpace();
      if (this.peek() === "{") {
        var body = this.readBraced();
        attrs.push({ name: name, value: { kind: "path", path: parsePath(body, this.loopVars, this.at, this.source) } });
      } else if (this.peek() === '"' ) {
        attrs.push({ name: name, value: { kind: "static", value: this.readString() } });
      } else {
        this.fail("attribute values must be quoted or an interpolation");
      }
      continue;
    }

    // A bare attribute is a boolean: rendered when the path is true.
    attrs.push({ name: name, value: { kind: "toggle" } });
  }

  if (selfClosing || VOID_TAGS[tag] === 1) {
    return { op: "element", tag: tag, attrs: attrs, children: [] };
  }

  var children = this.parseChildren(tag);
  return { op: "element", tag: tag, attrs: attrs, children: children };
};

Parser.prototype.parseBraced = function () {
  var start = this.at;
  var body = this.readBraced().trim();

  // {__raw(path)}
  if (body.startsWith("__raw(") && body.endsWith(")")) {
    var inner = body.slice("__raw(".length, body.length - 1);
    return { op: "raw", path: parsePath(inner, this.loopVars, start, this.source) };
  }

  // {path && <element>…</element>}
  var andMatch = body.match(/^(.+?)\s*&&\s*</);
  if (andMatch) {
    var condition = parsePath(andMatch[1], this.loopVars, start, this.source);
    var saved = this.at;
    this.at = start + 1 + body.indexOf("<");
    try {
      var taken = this.parseElement();
      var after = this.source.slice(this.at).replace(/^\s*/, "");
      if (after.startsWith("}")) {
        this.at = this.source.length - after.length + 1;
        return { op: "if", path: condition, then: [taken], otherwise: [] };
      }
      this.at = saved;
    } catch (err) {
      this.at = saved;
    }
    this.fail("could not read the element after `&&`");
  }

  // {path.map(function (item) { return <li>{item}</li>; })}
  // {path.map(item => <li>{item}</li>)}
  if (body.indexOf(".map(") !== -1) {
    var arrow = body.match(/^(.+?)\.map\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*=>/);
    var fn = body.match(/^(.+?)\.map\(\s*function\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{/);
    var iterable, item;
    if (arrow) {
      iterable = parsePath(arrow[1], this.loopVars, start, this.source);
      item = arrow[2];
    } else if (fn) {
      iterable = parsePath(fn[1], this.loopVars, start, this.source);
      item = fn[2];
    } else {
      this.fail("only `path.map(item => …)` and `path.map(function (item) { … })` iterate");
    }

    var innerStart = start + 1 + body.indexOf("<");
    if (innerStart <= start) this.fail("a map body must contain markup");

    var previous = this.loopVars[item];
    this.loopVars[item] = 1;
    var body0;
    try {
      this.at = innerStart;
      body0 = this.parseElement();
    } finally {
      if (previous === undefined) delete this.loopVars[item];
      else this.loopVars[item] = previous;
    }

    // Step past whatever closes the call: `})`, `)}`, `); })`, whitespace.
    var rest = this.source.slice(this.at);
    var close = rest.match(/^\s*;?\s*\}?\s*\)?\s*\}?\s*/);
    this.at += close ? close[0].length : 0;

    return { op: "for", path: iterable, item: item, body: [body0] };
  }

  // A plain path: interpolate it, escaped.
  return { op: "expr", path: parsePath(body, this.loopVars, start, this.source) };
};

// The entry point QuickJS calls. `source` is the template; the result is the IR as a JSON string.
function transform(source) {
  var parser = new Parser(source);
  var ops = parser.parseChildren(null);
  parser.skipSpace();
  if (parser.at !== source.length) parser.fail("trailing input");

  return JSON.stringify({ ops: ops });
}
