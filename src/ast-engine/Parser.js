
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const filePath = process.argv[2];

if (!filePath) {
    console.log("Usage: node ast-engine/parser.js <file>");
    process.exit(1);
}

const code = fs.readFileSync(filePath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous",
    plugins: ["jsx", "typescript"]
});

const sources = [];
const sinks = [];
const taintedVariables = new Set();

// Check whether an expression contains an untrusted source
function containsSource(node) {
    if (!node || typeof node !== "object") return false;

    if (node.type === "MemberExpression") {
        const object = node.object;
        const property = node.property;

        if (object.type === "Identifier" &&
            property.type === "Identifier") {

            const patterns = {
                location: ["search", "hash"],
                document: ["URL", "referrer"],
                req: ["query", "body", "params"]
            };

            if (patterns[object.name] &&
                patterns[object.name].includes(property.name)) {
                return true;
            }
        }
    }

    return Object.keys(node).some(key => {
        if (["loc", "start", "end", "extra"].includes(key)) {
            return false;
        }

        const value = node[key];

        return Array.isArray(value)
            ? value.some(containsSource)
            : containsSource(value);
    });
}

// Collect variable names used in an expression
function getIdentifiers(node, result = []) {
    if (!node || typeof node !== "object") return result;

    if (node.type === "Identifier") {
        result.push(node.name);
        return result;
    }

    Object.keys(node).forEach(key => {
        if (["loc", "start", "end", "extra"].includes(key)) return;

        const value = node[key];

        if (Array.isArray(value)) {
            value.forEach(item => getIdentifiers(item, result));
        } else if (value && typeof value === "object") {
            getIdentifiers(value, result);
        }
    });

    return result;
}

// Step 1: Detect source variables
traverse(ast, {
    VariableDeclarator(path) {
        const node = path.node;

        if (
            node.id.type === "Identifier" &&
            containsSource(node.init)
        ) {
            taintedVariables.add(node.id.name);

            sources.push({
                variable: node.id.name,
                line: node.loc.start.line
            });
        }
    }
});

// Step 2: Track simple variable-to-variable data flow
let changed = true;

while (changed) {
    changed = false;

    traverse(ast, {
        VariableDeclarator(path) {
            const node = path.node;

            if (
                node.id.type === "Identifier" &&
                !taintedVariables.has(node.id.name) &&
                getIdentifiers(node.init).some(name =>
                    taintedVariables.has(name)
                )
            ) {
                taintedVariables.add(node.id.name);
                changed = true;
            }
        },

        AssignmentExpression(path) {
            const node = path.node;

            if (
                node.left.type === "Identifier" &&
                !taintedVariables.has(node.left.name) &&
                getIdentifiers(node.right).some(name =>
                    taintedVariables.has(name)
                )
            ) {
                taintedVariables.add(node.left.name);
                changed = true;
            }
        }
    });
}

// Step 3: Detect dangerous sinks and source-to-sink flows
traverse(ast, {
    AssignmentExpression(path) {
        const node = path.node;

        if (
            node.left.type === "MemberExpression" &&
            node.left.property.type === "Identifier" &&
            ["innerHTML", "outerHTML"].includes(
                node.left.property.name
            )
        ) {
            const identifiers = getIdentifiers(node.right);

            const matched = identifiers.find(name =>
                taintedVariables.has(name)
            );

            const directSource = containsSource(node.right);

            sinks.push({
                name: node.left.property.name,
                line: node.loc.start.line,
                reachable: directSource || Boolean(matched),
                variable: matched || "Direct source"
            });
        }
    },

    CallExpression(path) {
        const node = path.node;

        if (
            node.callee.type === "Identifier" &&
            node.callee.name === "eval"
        ) {
            const identifiers = node.arguments.flatMap(arg =>
                getIdentifiers(arg)
            );

            const matched = identifiers.find(name =>
                taintedVariables.has(name)
            );

            const directSource = containsSource(node.arguments);

            sinks.push({
                name: "eval()",
                line: node.loc.start.line,
                reachable: directSource || Boolean(matched),
                variable: matched || "Direct source"
            });
        }
    }
});

// Step 4: Display analysis results
console.log("\nPROOFLOCK DATA-FLOW ANALYSIS");
console.log("============================");

console.log("\nUNTRUSTED SOURCES:");

if (sources.length === 0) {
    console.log("No sources found.");
}

sources.forEach(source => {
    console.log(
        "Source variable:", source.variable,
        "| Line:", source.line
    );
});

console.log("\nDANGEROUS SINKS:");

if (sinks.length === 0) {
    console.log("No sinks found.");
}

sinks.forEach(sink => {
    console.log(
        "Sink:", sink.name,
        "| Line:", sink.line
    );

    if (sink.reachable) {
        console.log(
            "Data Flow: SOURCE TO SINK DETECTED",
            "| Variable:", sink.variable
        );
    } else {
        console.log("Data Flow: No tainted input detected");
    }
});

// Step 5: Summary
console.log("\nANALYSIS SUMMARY");
console.log("----------------------------");
console.log("Total sources:", sources.length);
console.log("Total sinks:", sinks.length);

console.log(
    "Potential source-to-sink flows:",
    sinks.filter(sink => sink.reachable).length
);
