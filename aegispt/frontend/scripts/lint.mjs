#!/usr/bin/env node
/**
 * Zero-dependency AST linter backed by the locally installed TypeScript compiler.
 * Checks static code hygiene, security invariants, and basic React/a11y rules offline and in CI.
 */
import fs from "node:fs";
import path from "node:path";
import ts from "typescript";

const ROOT = path.resolve(import.meta.dirname, "..");
const SRC_DIR = path.join(ROOT, "src");

function collectFiles(dir) {
  const results = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...collectFiles(full));
    } else if (/\.(ts|tsx)$/.test(entry.name) && !entry.name.endsWith(".d.ts")) {
      results.push(full);
    }
  }
  return results.sort();
}

function getLineCol(sf, pos) {
  const { line, character } = sf.getLineAndCharacterOfPosition(pos);
  return `${line + 1}:${character + 1}`;
}

const errors = [];

function report(file, sf, nodeOrPos, rule, message) {
  const pos = typeof nodeOrPos === "number" ? nodeOrPos : nodeOrPos.getStart(sf);
  const rel = path.relative(ROOT, file);
  errors.push(`${rel}:${getLineCol(sf, pos)}  [${rule}] ${message}`);
}

for (const file of collectFiles(SRC_DIR)) {
  const text = fs.readFileSync(file, "utf8");
  const isTest = file.includes(`${path.sep}__tests__${path.sep}`);
  const scriptKind = file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ES2020, true, scriptKind);

  // Check for banned query-string auth token patterns in app source
  if (!isTest) {
    const tokenQueryIdx = text.indexOf("?token=");
    if (tokenQueryIdx !== -1) {
      report(file, sf, tokenQueryIdx, "no-query-token", "Do not pass API tokens via ?token= query strings; use Authorization header or single-use ?ticket=.");
    }
  }

  function visit(node) {
    // Disallow explicit `any` outside tests
    if (!isTest && node.kind === ts.SyntaxKind.AnyKeyword) {
      report(file, sf, node, "no-explicit-any", "Avoid explicit 'any'; use strict types or 'unknown'.");
    }

    // Disallow native blocking browser dialogs (window.confirm / alert / prompt)
    if (ts.isCallExpression(node)) {
      const exprText = node.expression.getText(sf);
      if (
        !isTest &&
        (exprText === "window.confirm" ||
          exprText === "window.alert" ||
          exprText === "window.prompt" ||
          exprText === "confirm" ||
          exprText === "alert" ||
          exprText === "prompt")
      ) {
        report(file, sf, node, "no-native-dialog", `Avoid blocking dialog '${exprText}()'; use ConfirmDialog or ToastBar.`);
      }

      if (!isTest && exprText === "console.log") {
        report(file, sf, node, "no-console-log", "Avoid console.log in production frontend code.");
      }

      // Disallow dangerouslySetInnerHTML / eval
      if (exprText === "eval") {
        report(file, sf, node, "no-eval", "Do not use eval().");
      }
    }

    // Disallow dangerouslySetInnerHTML JSX attribute
    if (ts.isJsxAttribute(node) && node.name.getText(sf) === "dangerouslySetInnerHTML") {
      report(file, sf, node, "no-danger", "Avoid dangerouslySetInnerHTML.");
    }

    // Disallow == / != (except null checks)
    if (
      ts.isBinaryExpression(node) &&
      (node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken ||
        node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken)
    ) {
      const leftNull = node.left.kind === ts.SyntaxKind.NullKeyword;
      const rightNull = node.right.kind === ts.SyntaxKind.NullKeyword;
      if (!leftNull && !rightNull) {
        report(file, sf, node.operatorToken, "eqeqeq", "Use strict equality (=== / !==).");
      }
    }

    // Require focus-visible/ring whenever focus:outline-none is used on interactive JSX className
    if (ts.isJsxAttribute(node) && node.name.getText(sf) === "className" && node.initializer) {
      const raw = node.initializer.getText(sf);
      if (raw.includes("focus:outline-none") && !raw.includes("focus:ring") && !raw.includes("focus-visible:ring")) {
        report(
          file,
          sf,
          node,
          "a11y-focus-ring",
          "Elements with 'focus:outline-none' must provide a visible 'focus:ring-*' or 'focus-visible:ring-*' indicator."
        );
      }
    }

    ts.forEachChild(node, visit);
  }

  visit(sf);
}

if (errors.length > 0) {
  console.error(`Lint failed with ${errors.length} issue(s):\n`);
  for (const err of errors) {
    console.error(`  ${err}`);
  }
  process.exit(1);
}

console.log(`Lint passed (${collectFiles(SRC_DIR).length} TypeScript/TSX files checked).`);
