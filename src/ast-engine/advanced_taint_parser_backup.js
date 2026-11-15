
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const filePath = __dirname + "/advanced_taint_sample.js";
const code = fs.readFileSync(filePath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

const taintedVariables = new Set();
const findings = [];

const dangerousProperties = [
    "innerHTML",
    "outerHTML"
];

// Check whether an expression contains untrusted data.
function isTainted(node) {
    if (!node) return false;

    if (node.type === "Identifier") {
        return taintedVariables.has(node.name);
    }

    if (node.type === "MemberExpression") {
        if (
            node.object.type === "Identifier" &&
            node.object.name === "location" &&
            node.property.type === "Identifier" &&
            ["search", "hash"].includes(node.property.name)
        ) {
            return true;
        }

        return isTainted(node.object);
    }

    if (
        node.type === "BinaryExpression" ||
        node.type === "LogicalExpression"
    ) {
        return isTainted(node.left) ||
            isTainted(node.right);
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

// Detect untrusted source and propagate taint.
traverse(ast, {
    VariableDeclarator(path) {
        const { id, init } = path.node;

        if (
            id.type === "Identifier" &&
            isTainted(init)
        ) {
            taintedVariables.add(id.name);
        }
    },

    AssignmentExpression(path) {
        const { left, right } = path.node;

        if (
            left.type === "Identifier" &&
            isTainted(right)
        ) {
            taintedVariables.add(left.name);
        }
    }
});

// Detect dangerous sinks.
traverse(ast, {
    AssignmentExpression(path) {
        const { left, right } = path.node;

        if (
            left.type === "MemberExpression" &&
            left.property.type === "Identifier" &&
            dangerousProperties.includes(left.property.name) &&
            isTainted(right)
        ) {
            findings.push({
                sink: left.property.name,
                line: path.node.loc.start.line
            });
        }
    },

    CallExpression(path) {
        const callee = path.node.callee;

        // eval(userInput)
        if (
            callee.type === "Identifier" &&
            callee.name === "eval" &&
            path.node.arguments.some(isTainted)
        ) {
            findings.push({
                sink: "eval()",
                line: path.node.loc.start.line
            });
        }

        // document.write(userInput)
        if (
            callee.type === "MemberExpression" &&
            callee.object.type === "Identifier" &&
            callee.object.name === "document" &&
            callee.property.type === "Identifier" &&
            callee.property.name === "write" &&
            path.node.arguments.some(isTainted)
        ) {
            findings.push({
                sink: "document.write()",
                line: path.node.loc.start.line
            });
        }
    }
});

// Display findings.
console.log("\nADVANCED TAINT ANALYSIS");
console.log("----------------------------------");

console.log("UNTRUSTED SOURCE: location.search");
console.log("Tainted variables:", [...taintedVariables].join(", "));

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

// Test 5: Reassignment with safe data
// Test 5: Reassignment with safe data
let reassignedValue = location.search;

reassignedValue = "This is safe data";

document.getElementById("safeOutput").innerHTML = reassignedValue;