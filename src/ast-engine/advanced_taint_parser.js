const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const path = require("path");

// Accept the file path from Python (process.argv[2]), fallback to sample.js if none provided
const inputPath = process.argv[2] || "./sample.js";
const filePath = path.resolve(process.cwd(), inputPath);

const code = fs.readFileSync(filePath, "utf8");
const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

const taintedVariables = new Set();
const findings = [];

const dangerousProperties = ["innerHTML", "outerHTML"];

function isSource(node) {
    return node &&
        node.type === "MemberExpression" &&
        node.object.type === "Identifier" &&
        node.object.name === "location" &&
        node.property.type === "Identifier" &&
        ["search", "hash"].includes(node.property.name);
}

function isTainted(node) {
    if (!node) return false;

    if (node.type === "Identifier") {
        return taintedVariables.has(node.name);
    }

    if (isSource(node)) return true;

    if (node.type === "MemberExpression") {
        return isTainted(node.object);
    }

    if (
        node.type === "BinaryExpression" ||
        node.type === "LogicalExpression"
    ) {
        return isTainted(node.left) || isTainted(node.right);
    }

    if (node.type === "ConditionalExpression") {
        return isTainted(node.test) ||
            isTainted(node.consequent) ||
            isTainted(node.alternate);
    }

    if (node.type === "TemplateLiteral") {
        return node.expressions.some(isTainted);
    }

    if (node.type === "CallExpression") {
        return node.arguments.some(isTainted);
    }

    if (node.type === "ArrayExpression") {
        return node.elements.some(isTainted);
    }

    if (node.type === "ObjectExpression") {
        return node.properties.some(property =>
            property.type === "ObjectProperty" &&
            isTainted(property.value)
        );
    }

    return false;
}

// Process statements in source order.
function analyzeStatements(statements) {
    for (const statement of statements) {

        if (statement.type === "VariableDeclaration") {
            for (const declaration of statement.declarations) {
                if (declaration.id.type === "Identifier") {
                    const name = declaration.id.name;

                    if (isTainted(declaration.init)) {
                        taintedVariables.add(name);
                    } else {
                        taintedVariables.delete(name);
                    }
                }
            }
        }

        if (statement.type === "ExpressionStatement") {
            const expression = statement.expression;

            if (expression.type === "AssignmentExpression") {
                const { left, right } = expression;

                if (
                    left.type === "Identifier" &&
                    expression.operator === "="
                ) {
                    if (isTainted(right)) {
                        taintedVariables.add(left.name);
                    } else {
                        taintedVariables.delete(left.name);
                    }
                }

                // Detect HTML assignment sinks.
                if (
                    left.type === "MemberExpression" &&
                    left.property.type === "Identifier" &&
                    dangerousProperties.includes(left.property.name) &&
                    isTainted(right)
                ) {
                    findings.push({
                        sink: left.property.name,
                        line: expression.loc.start.line
                    });
                }
            }

            if (expression.type === "CallExpression") {
                const callee = expression.callee;

                if (
                    callee.type === "Identifier" &&
                    callee.name === "eval" &&
                    expression.arguments.some(isTainted)
                ) {
                    findings.push({
                        sink: "eval()",
                        line: expression.loc.start.line
                    });
                }

                if (
                    callee.type === "MemberExpression" &&
                    callee.object.type === "Identifier" &&
                    callee.object.name === "document" &&
                    callee.property.name === "write" &&
                    expression.arguments.some(isTainted)
                ) {
                    findings.push({
                        sink: "document.write()",
                        line: expression.loc.start.line
                    });
                }
            }
        }
    }
}

analyzeStatements(ast.program.body);

console.log("\nFLOW-SENSITIVE TAINT ANALYSIS");
console.log("----------------------------------");

console.log("UNTRUSTED SOURCE: location.search");
console.log(
    "Tainted variables:",
    [...taintedVariables].join(", ")
);

console.log("\nDANGEROUS DATA-FLOW FINDINGS:");

if (findings.length === 0) {
    console.log("No dangerous data flows detected.");
}

findings.forEach((finding, index) => {
    console.log("----------------------------------");
    console.log("Finding:", index + 1);
    console.log("Dangerous Sink:", finding.sink);
    console.log("Source-to-Sink Flow: DETECTED");
    console.log("Original Source Line:", finding.line);
});

console.log("----------------------------------");
console.log("Total dangerous flows:", findings.length);
