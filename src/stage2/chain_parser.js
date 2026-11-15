
const fs = require("fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

const filePath = process.argv[2];

if (!filePath) {
    console.log("Usage: node chain_parser.js <javascript-file>");
    process.exit(1);
}

const code = fs.readFileSync(filePath, "utf8");

const ast = parser.parse(code, {
    sourceType: "unambiguous"
});

const taintedVariables = new Set();
const taintedFunctions = new Set();
const functions = new Map();
const findings = [];

function isSource(node) {
    if (!node || node.type !== "MemberExpression") {
        return false;
    }

    const object = node.object;
    const property = node.property;

    const propName = property.name || property.value;

    if (
        object.type === "Identifier" &&
        object.name === "location" &&
        ["search", "hash"].includes(propName)
    ) {
        return true;
    }

    if (
        object.type === "Identifier" &&
        object.name === "document" &&
        propName === "URL"
    ) {
        return true;
    }

    return false;
}

// Recursively check whether an expression contains tainted data.
function isTainted(node, names, taintedFunctions) {
    if (!node) return false;

    if (isSource(node)) return true;

    if (node.type === "Identifier") {
        return names.has(node.name);
    }

    if (node.type === "CallExpression") {
        if (
            node.callee.type === "Identifier" &&
            taintedFunctions.has(node.callee.name)
        ) {
            return true;
        }

        return node.arguments.some(argument =>
            isTainted(argument, names, taintedFunctions)
        );
    }

    if (
        node.type === "BinaryExpression" ||
        node.type === "LogicalExpression"
    ) {
        return (
            isTainted(node.left, names, taintedFunctions) ||
            isTainted(node.right, names, taintedFunctions)
        );
    }

    if (node.type === "ConditionalExpression") {
        return (
            isTainted(node.test, names, taintedFunctions) ||
            isTainted(node.consequent, names, taintedFunctions) ||
            isTainted(node.alternate, names, taintedFunctions)
        );
    }

    if (node.type === "TemplateLiteral") {
        return node.expressions.some(expression =>
            isTainted(expression, names, taintedFunctions)
        );
    }

    if (node.type === "MemberExpression") {
        return isTainted(node.object, names, taintedFunctions);
    }

    if (
        node.type === "UnaryExpression" ||
        node.type === "AwaitExpression"
    ) {
        return isTainted(node.argument, names, taintedFunctions);
    }

    if (node.type === "ArrayExpression") {
        return node.elements.some(element =>
            isTainted(element, names, taintedFunctions)
        );
    }

    if (node.type === "SequenceExpression") {
        return node.expressions.some(expression =>
            isTainted(expression, names, taintedFunctions)
        );
    }

    return false;
}

// STEP 1: Identify untrusted source variables.
traverse(ast, {
    VariableDeclarator(path) {
        if (
            path.node.id.type === "Identifier" &&
            isSource(path.node.init)
        ) {
            taintedVariables.add(path.node.id.name);

            console.log(
                "UNTRUSTED SOURCE:",
                path.node.id.name,
                "| Line:",
                path.node.loc.start.line
            );
        }
    }
});

// STEP 2: Collect function declarations.
traverse(ast, {
    FunctionDeclaration(path) {
        if (path.node.id) {
            functions.set(path.node.id.name, path.node);
        }
    }
});

// STEP 3: Find which function parameters receive tainted arguments.
function buildParameterTaint() {
    const parameterTaint = new Map();

    traverse(ast, {
        CallExpression(path) {
            if (path.node.callee.type !== "Identifier") {
                return;
            }

            const name = path.node.callee.name;
            const fn = functions.get(name);

            if (!fn) return;

            fn.params.forEach((parameter, index) => {
                if (parameter.type !== "Identifier") return;

                const argument = path.node.arguments[index];

                if (
                    argument &&
                    isTainted(
                        argument,
                        taintedVariables,
                        taintedFunctions
                    )
                ) {
                    if (!parameterTaint.has(name)) {
                        parameterTaint.set(name, new Set());
                    }

                    parameterTaint.get(name).add(parameter.name);
                }
            });
        }
    });

    return parameterTaint;
}

// STEP 4: Determine which functions return tainted data.
// Repeat until no new tainted functions are discovered.
let changed = true;
let parameterTaint = new Map();

while (changed) {
    changed = false;

    parameterTaint = buildParameterTaint();

    traverse(ast, {
        ReturnStatement(path) {
            const functionPath = path.getFunctionParent();

            if (
                !functionPath ||
                functionPath.node.type !== "FunctionDeclaration"
            ) {
                return;
            }

            const name = functionPath.node.id.name;
            const parameters = parameterTaint.get(name) || new Set();

            const availableNames = new Set([
                ...taintedVariables,
                ...parameters
            ]);

            if (
                isTainted(
                    path.node.argument,
                    availableNames,
                    taintedFunctions
                ) &&
                !taintedFunctions.has(name)
            ) {
                taintedFunctions.add(name);
                changed = true;
            }
        }
    });
}

// Recalculate parameter taint after function return analysis.
parameterTaint = buildParameterTaint();

// STEP 5: Detect dangerous sinks.
traverse(ast, {
    AssignmentExpression(path) {
        const left = path.node.left;
        const right = path.node.right;

        if (
            left.type !== "MemberExpression" ||
            left.property.type !== "Identifier" ||
            !["innerHTML", "outerHTML"].includes(left.property.name)
        ) {
            return;
        }

        const functionPath = path.getFunctionParent();
        const availableNames = new Set(taintedVariables);

        if (
            functionPath &&
            functionPath.node.type === "FunctionDeclaration"
        ) {
            const name = functionPath.node.id.name;
            const parameters = parameterTaint.get(name) || new Set();

            parameters.forEach(parameter => {
                availableNames.add(parameter);
            });
        }

        if (
            isTainted(
                right,
                availableNames,
                taintedFunctions
            )
        ) {
            findings.push({
                function: functionPath && functionPath.node.id
                    ? functionPath.node.id.name
                    : "Global scope",
                sink: left.property.name,
                line: path.node.loc.start.line
            });
        }
    },

    CallExpression(path) {
        if (
            path.node.callee.type === "Identifier" &&
            path.node.callee.name === "eval"
        ) {
            if (
                isTainted(
                    path.node.arguments[0],
                    taintedVariables,
                    taintedFunctions
                )
            ) {
                findings.push({
                    function: "eval",
                    sink: "eval()",
                    line: path.node.loc.start.line
                });
            }
        }
    }
});

// STEP 6: Display analysis results.
console.log("\nMULTI-FUNCTION DATA-FLOW ANALYSIS");
console.log("----------------------------------");

console.log(
    "Tainted functions:",
    [...taintedFunctions].join(", ") || "None"
);

console.log(
    "Tainted variables:",
    [...taintedVariables].join(", ") || "None"
);

console.log(
    "Tainted function parameters:",
    [...parameterTaint.entries()]
        .map(([name, params]) => name + ": " + [...params].join(", "))
        .join(" | ") || "None"
);

findings.forEach(finding => {
    console.log("Function:", finding.function);
    console.log("Dangerous Sink:", finding.sink);
    console.log("Line:", finding.line);
    console.log("RESULT: SOURCE TO SINK FLOW DETECTED");
    console.log("----------------------------------");
});

console.log("Total function-chain flows:", findings.length);
